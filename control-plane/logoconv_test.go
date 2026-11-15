package controlplane

// docs/66 2a.8: the logo decode step. These call ConvertLogo directly; logoconv_child_test.go runs the same
// step in a real child process under its resource limits.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"math/rand"
	"strings"
	"testing"
)

func solidPNG(t testing.TB, w, h int, c color.NRGBA) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.R, c.G, c.B, c.A
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func noisePNG(t testing.TB, w, h int) []byte {
	t.Helper()
	rng := rand.New(rand.NewSource(1))
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), 255
	}
	var b bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := enc.Encode(&b, image.Image(img)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func pngChunk(typ string, data []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
	b.WriteString(typ)
	b.Write(data)
	_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(append([]byte(typ), data...)))
	return b.Bytes()
}

// injectPNGChunk puts a chunk right after IHDR (offset 8 + 25).
func injectPNGChunk(png []byte, typ string, data []byte) []byte {
	out := append([]byte(nil), png[:33]...)
	out = append(out, pngChunk(typ, data)...)
	return append(out, png[33:]...)
}

// bombPNG is a PNG that is ONLY a header claiming w x h: there is no pixel data, so if the decoder ever
// reached the pixels it would fail with "unreadable", not "dimensions": the dimension error proves the check
// ran FIRST.
func bombPNG(w, h uint32) []byte {
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], w)
	binary.BigEndian.PutUint32(ihdr[4:], h)
	ihdr[8], ihdr[9] = 8, 6
	out := append([]byte(nil), logoPNGMagic...)
	out = append(out, pngChunk("IHDR", ihdr)...)
	return append(out, pngChunk("IEND", nil)...)
}

func outDims(t testing.TB, out []byte) (int, int) {
	t.Helper()
	cfg, err := png.DecodeConfig(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("output is not a PNG: %v", err)
	}
	return cfg.Width, cfg.Height
}

func wantLogoErr(t *testing.T, what string, raw []byte, want *LogoError) {
	t.Helper()
	out, err := ConvertLogo(raw)
	if err == nil {
		t.Errorf("%s: accepted (%d bytes out)", what, len(out))
		return
	}
	if want != nil && !errors.Is(err, want) {
		t.Errorf("%s: got %v want %v", what, err, want)
	}
}

func TestLogoDimensionBombsAreRefusedBeforeAnyPixelDecode(t *testing.T) {
	for _, d := range [][2]uint32{{30000, 30000}, {1, 1000000}, {1000000, 1}, {2049, 1}, {1, 2049}, {2000, 2001},
		{2048, 2048}, {2147483647, 2}, {0, 5}} {
		raw := bombPNG(d[0], d[1])
		out, err := ConvertLogo(raw)
		if err == nil {
			t.Errorf("%dx%d accepted (%d bytes)", d[0], d[1], len(out))
			continue
		}
		// A zero axis is refused by the PNG parser itself (unreadable); every positive one by OUR gate.
		if d[0] > 0 && !errors.Is(err, ErrLogoDimensions) {
			t.Errorf("%dx%d: got %v, want the dimension refusal (the gate must run before decode)", d[0], d[1], err)
		}
	}
}

func TestLogoHugeAxesAreRefused(t *testing.T) {
	wantLogoErr(t, "2^31-1 square", bombPNG(2147483647, 2147483647), nil)
}

func TestLogoLargestAllowedImageConverts(t *testing.T) {
	out, err := ConvertLogo(solidPNG(t, 2000, 2000, color.NRGBA{R: 53, G: 101, B: 74, A: 255}))
	if err != nil {
		t.Fatal(err)
	}
	if w, h := outDims(t, out); w != 256 || h != 256 {
		t.Errorf("scaled to %dx%d, want 256x256 (inside 512x256, aspect kept)", w, h)
	}
}

func TestLogoScalingNeverEnlargesAndKeepsAspect(t *testing.T) {
	out, _ := ConvertLogo(solidPNG(t, 100, 50, color.NRGBA{A: 255}))
	if w, h := outDims(t, out); w != 100 || h != 50 {
		t.Errorf("small image changed size: %dx%d", w, h)
	}
	out, _ = ConvertLogo(solidPNG(t, 1000, 500, color.NRGBA{A: 255}))
	if w, h := outDims(t, out); w != 512 || h != 256 {
		t.Errorf("wide image: %dx%d", w, h)
	}
	out, _ = ConvertLogo(solidPNG(t, 200, 1000, color.NRGBA{A: 255}))
	if w, h := outDims(t, out); w != 51 || h != 256 {
		t.Errorf("tall image: %dx%d", w, h)
	}
}

func TestLogoKeepsAlpha(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	img.SetNRGBA(1, 1, color.NRGBA{R: 200, G: 10, B: 10, A: 255})
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	out, err := ConvertLogo(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	dec, _ := png.Decode(bytes.NewReader(out))
	if _, _, _, a := dec.At(0, 0).RGBA(); a != 0 {
		t.Errorf("transparent pixel became opaque (alpha %d)", a)
	}
	if r, _, _, a := dec.At(1, 1).RGBA(); a == 0 || r == 0 {
		t.Errorf("opaque pixel lost")
	}
}

func TestLogoAnimatedGIFUsesOnlyTheFirstFrame(t *testing.T) {
	pal := color.Palette{color.NRGBA{255, 0, 0, 255}, color.NRGBA{0, 255, 0, 255}, color.NRGBA{0, 0, 255, 255}}
	g := &gif.GIF{}
	for i := 0; i < 3; i++ {
		f := image.NewPaletted(image.Rect(0, 0, 40, 40), pal)
		for p := range f.Pix {
			f.Pix[p] = uint8(i)
		}
		g.Image = append(g.Image, f)
		g.Delay = append(g.Delay, 10)
	}
	var b bytes.Buffer
	if err := gif.EncodeAll(&b, g); err != nil {
		t.Fatal(err)
	}
	out, err := ConvertLogo(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	dec, _ := png.Decode(bytes.NewReader(out))
	r, gr, bl, a := dec.At(5, 5).RGBA()
	if r>>8 != 255 || gr != 0 || bl != 0 || a>>8 != 255 {
		t.Errorf("not the first (red) frame: %d %d %d %d", r>>8, gr>>8, bl>>8, a>>8)
	}
	// Static GIF with trailing frames after the first is fine; a GIF cut off mid-frame is not.
	wantLogoErr(t, "truncated gif", b.Bytes()[:60], ErrLogoUnreadable)
}

func TestLogoJPEGConvertsAndDropsEXIF(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 64, 32))
	for i := range img.Pix {
		img.Pix[i] = 200
	}
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, nil); err != nil {
		t.Fatal(err)
	}
	raw := b.Bytes()
	secret := []byte("Exif\x00\x00SECRET-GPS-51.5N")
	seg := append([]byte{0xFF, 0xE1, byte((len(secret) + 2) >> 8), byte((len(secret) + 2) & 0xff)}, secret...)
	withExif := append(append(append([]byte(nil), raw[:2]...), seg...), raw[2:]...)
	if !bytes.Contains(withExif, []byte("SECRET-GPS")) {
		t.Fatal("test setup")
	}
	out, err := ConvertLogo(withExif)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("SECRET-GPS")) || bytes.Contains(out, []byte("Exif")) {
		t.Error("EXIF survived the conversion")
	}
	wantLogoErr(t, "jpeg truncated", withExif[:len(withExif)/2], ErrLogoUnreadable)
	wantLogoErr(t, "jpeg with trailing bytes", append(append([]byte(nil), raw...), []byte("<script>")...), ErrLogoUnreadable)
	// Garbage that ENDS in FF D9 (a suffix check would accept it), and two concatenated JPEGs.
	wantLogoErr(t, "jpeg + garbage + FF D9", append(append([]byte(nil), raw...), 'x', 'y', 0xFF, 0xD9), ErrLogoUnreadable)
	wantLogoErr(t, "two concatenated jpegs", append(append([]byte(nil), raw...), raw...), ErrLogoUnreadable)
	wantLogoErr(t, "jpeg + FF D9 FF D9", append(append([]byte(nil), raw...), 0xFF, 0xD9), ErrLogoUnreadable)
	// A real progressive/standard file still passes the walk: end == len.
	if end, ok := jpegStreamEnd(raw); !ok || end != len(raw) {
		t.Errorf("walk of a valid jpeg: end=%d ok=%v len=%d", end, ok, len(raw))
	}
}

func TestLogoMetadataAndPolyglotsDoNotSurvive(t *testing.T) {
	base := solidPNG(t, 32, 32, color.NRGBA{R: 1, G: 2, B: 3, A: 255})
	for _, typ := range []string{"tEXt", "iTXt", "zTXt", "eXIf", "iCCP", "pHYs"} {
		raw := injectPNGChunk(base, typ, []byte("kw\x00<script>alert(1)</script> GPS-SECRET"))
		out, err := ConvertLogo(raw)
		if err != nil {
			t.Errorf("%s chunk: %v", typ, err)
			continue
		}
		if bytes.Contains(out, []byte("script")) || bytes.Contains(out, []byte("GPS-SECRET")) {
			t.Errorf("%s chunk content survived", typ)
		}
	}
	// A polyglot (valid PNG followed by markup) is refused outright: the trailing bytes are never kept.
	wantLogoErr(t, "png+script", append(append([]byte(nil), base...), []byte("<script>alert(1)</script>")...), ErrLogoUnreadable)
	wantLogoErr(t, "png+zip", append(append([]byte(nil), base...), []byte("PK\x03\x04")...), ErrLogoUnreadable)
	// The output only ever carries the PNG signature, IHDR, IDAT and IEND.
	out, _ := ConvertLogo(injectPNGChunk(base, "tEXt", []byte("a\x00b")))
	for _, banned := range []string{"tEXt", "iTXt", "zTXt", "eXIf", "iCCP", "gAMA", "sRGB", "pHYs", "tIME"} {
		if bytes.Contains(out, []byte(banned)) {
			t.Errorf("output carries ancillary chunk %s", banned)
		}
	}
}

func TestLogoTruncatedAndMalformedInputIsRefused(t *testing.T) {
	base := solidPNG(t, 64, 64, color.NRGBA{R: 9, A: 255})
	wantLogoErr(t, "empty", nil, ErrLogoUnreadable)
	wantLogoErr(t, "half a png", base[:len(base)/2], ErrLogoUnreadable)
	wantLogoErr(t, "png without IEND", base[:len(base)-12], ErrLogoUnreadable)
	wantLogoErr(t, "png with a bad crc", func() []byte {
		b := append([]byte(nil), base...)
		b[len(b)-20] ^= 0xFF
		return b
	}(), ErrLogoUnreadable)
	wantLogoErr(t, "signature only", logoPNGMagic, ErrLogoUnreadable)
	wantLogoErr(t, "jpeg magic only", []byte{0xFF, 0xD8, 0xFF}, ErrLogoUnreadable)
	wantLogoErr(t, "gif header only", []byte("GIF89a"), ErrLogoUnreadable)
}

func TestLogoSVGWebPAndEverythingElseAreRefused(t *testing.T) {
	wantLogoErr(t, "svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><script>alert(1)</script></svg>`), ErrLogoFormat)
	wantLogoErr(t, "svg with xml prolog", []byte(`<?xml version="1.0"?><svg/>`), ErrLogoFormat)
	wantLogoErr(t, "webp", append([]byte("RIFF\x24\x00\x00\x00WEBPVP8 "), make([]byte, 40)...), ErrLogoFormat)
	wantLogoErr(t, "html", []byte("<html><body>x</body></html>"), ErrLogoFormat)
	wantLogoErr(t, "pdf", []byte("%PDF-1.4 ..."), ErrLogoFormat)
	wantLogoErr(t, "bmp", []byte("BM......"), ErrLogoFormat)
	wantLogoErr(t, "oversize input", append(append([]byte(nil), logoPNGMagic...), make([]byte, LogoMaxInputBytes)...), ErrLogoTooBigInput)
}

func TestLogoOutputOverSixtyFourKiBIsRefused(t *testing.T) {
	raw := noisePNG(t, 150, 150) // incompressible, under the 128 KiB input cap
	if len(raw) > LogoMaxInputBytes {
		t.Fatalf("test image too big: %d", len(raw))
	}
	wantLogoErr(t, "noisy logo", raw, ErrLogoTooBigOutput)
	// The same size cap holds on what the parent re-verifies.
	if err := VerifyConvertedLogo(append(append([]byte(nil), logoPNGMagic...), make([]byte, LogoMaxOutputBytes)...)); err == nil {
		t.Error("oversize output verified")
	}
	good, _ := ConvertLogo(solidPNG(t, 64, 64, color.NRGBA{A: 255}))
	if err := VerifyConvertedLogo(good); err != nil {
		t.Errorf("good output refused: %v", err)
	}
	if err := VerifyConvertedLogo(append(append([]byte(nil), good...), 0)); err == nil {
		t.Error("output with trailing byte verified")
	}
	if err := VerifyConvertedLogo(bombPNG(600, 100)); err == nil {
		t.Error("output outside the box verified")
	}
	if err := VerifyConvertedLogo([]byte("not a png")); err == nil || strings.Contains(err.Error(), "not a png") {
		t.Errorf("garbage verified or echoed: %v", err)
	}
}

func TestLogoDecodedBoundsMustMatchTheConfig(t *testing.T) {
	// A GIF frame may sit inside a larger logical screen; one that overflows the screen is refused.
	pal := color.Palette{color.NRGBA{255, 0, 0, 255}, color.NRGBA{0, 0, 0, 0}}
	g := &gif.GIF{Config: image.Config{Width: 20, Height: 20, ColorModel: pal}}
	f := image.NewPaletted(image.Rect(5, 5, 15, 15), pal)
	g.Image, g.Delay = []*image.Paletted{f}, []int{0}
	var b bytes.Buffer
	if err := gif.EncodeAll(&b, g); err != nil {
		t.Fatal(err)
	}
	out, err := ConvertLogo(b.Bytes())
	if err != nil {
		t.Fatalf("sub-rectangle frame: %v", err)
	}
	if w, h := outDims(t, out); w != 10 || h != 10 {
		t.Errorf("frame size %dx%d", w, h)
	}
}

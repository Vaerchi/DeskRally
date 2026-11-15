package controlplane

// The logo decode/re-encode step (docs/66 2a.8, 2b.3). ConvertLogo is PURE and is only ever run inside the
// short-lived `controlplane logo-convert` child process (logoconv_child.go); the parent never decodes an
// upload. Conversion happens on an authenticated upload only, never on a public read.
//
//  1. Input is capped at 128 KiB (the parent already cut it; the child re-applies the cap through a limited
//     reader), and the format is decided by its magic bytes: PNG, JPEG or GIF. WebP and SVG are refused (no
//     decoder dependency, no rasteriser), and so is everything else.
//  2. image.DecodeConfig FIRST: positive dimensions, 2048 per axis, and the pixel product computed in int64 so
//     w*h cannot overflow, at most 4 megapixels. Nothing is decoded before that passes.
//  3. Decode (a GIF through gif.Decode, which returns the FIRST frame only; gif.DecodeAll is never used), then
//     assert the decoded bounds agree with the configured ones (a mismatch is a refusal). A GIF frame may be
//     a sub-rectangle of the logical screen, so for GIF the check is "inside the screen" rather than equality.
//  4. Truncated or malformed input, a PNG without IEND, and trailing bytes after a PNG's IEND, and a JPEG that does not end with its EOI marker, are
//     refused with the one generic message. (A GIF legitimately carries further frames after the first, so
//     trailing data is not an error there.)
//  5. Scale DOWN (never up) into a 512x256 box preserving aspect, keeping alpha, re-encode with the stdlib PNG
//     encoder. EXIF, XMP and ICC are never copied (only decoded pixels survive: a polyglot cannot). The result
//     must be at most 64 KiB, else "simplify the image".

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"math"
)

// Logo limits.
const (
	LogoMaxInputBytes   = 128 * 1024
	LogoMaxOutputBytes  = 64 * 1024
	LogoMaxAxis         = 2048
	LogoMaxPixels       = 4_000_000
	LogoBoxW            = 512
	LogoBoxH            = 256
	logoStdoutCap       = 128 * 1024
	logoStderrCap       = 256
	LogoDefaultDeadline = 3
)

// Logo conversion refusals. Each has a short fixed code the child prints on stderr and the parent maps back.
var (
	ErrLogoUnreadable   = &LogoError{Code: "E_READ", Msg: "image could not be read"}
	ErrLogoFormat       = &LogoError{Code: "E_FORMAT", Msg: "only PNG, JPEG and GIF logos are accepted (no WebP, no SVG)"}
	ErrLogoDimensions   = &LogoError{Code: "E_DIM", Msg: "image dimensions are too large (at most 2048x2048 and 4 megapixels)"}
	ErrLogoTooBigInput  = &LogoError{Code: "E_SIZE", Msg: "image file is larger than 128 KiB"}
	ErrLogoTooBigOutput = &LogoError{Code: "E_OUT", Msg: "simplify the image: the converted logo exceeds 64 KiB"}
)

// LogoError is a refusal the Owner can act on (as opposed to an infrastructure failure).
type LogoError struct {
	Code string
	Msg  string
}

func (e *LogoError) Error() string { return e.Msg }

func logoErrorByCode(code string) *LogoError {
	for _, e := range []*LogoError{ErrLogoUnreadable, ErrLogoFormat, ErrLogoDimensions, ErrLogoTooBigInput, ErrLogoTooBigOutput} {
		if e.Code == code {
			return e
		}
	}
	return nil
}

var (
	logoPNGMagic  = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	logoJPEGMagic = []byte{0xFF, 0xD8, 0xFF}
)

// ConvertLogo decodes raw (PNG, JPEG or GIF) and returns the derived PNG. See the package comment.
func ConvertLogo(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, ErrLogoUnreadable
	}
	if len(raw) > LogoMaxInputBytes {
		return nil, ErrLogoTooBigInput
	}
	var format string
	switch {
	case bytes.HasPrefix(raw, logoPNGMagic):
		format = "png"
	case bytes.HasPrefix(raw, logoJPEGMagic):
		format = "jpeg"
	case bytes.HasPrefix(raw, []byte("GIF87a")), bytes.HasPrefix(raw, []byte("GIF89a")):
		format = "gif"
	default:
		return nil, ErrLogoFormat // WebP (RIFF), SVG (text) and anything else
	}

	var cfg image.Config
	var err error
	switch format {
	case "png":
		cfg, err = png.DecodeConfig(bytes.NewReader(raw))
	case "jpeg":
		cfg, err = jpeg.DecodeConfig(bytes.NewReader(raw))
	case "gif":
		cfg, err = gif.DecodeConfig(bytes.NewReader(raw))
	}
	if err != nil {
		return nil, ErrLogoUnreadable
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > LogoMaxAxis || cfg.Height > LogoMaxAxis ||
		int64(cfg.Width)*int64(cfg.Height) > LogoMaxPixels {
		return nil, ErrLogoDimensions
	}

	rd := bytes.NewReader(raw)
	var img image.Image
	switch format {
	case "png":
		img, err = png.Decode(rd)
	case "jpeg":
		img, err = jpeg.Decode(rd)
	case "gif":
		img, err = gif.Decode(rd) // the FIRST frame only
	}
	if err != nil {
		return nil, ErrLogoUnreadable
	}
	if format == "png" && rd.Len() != 0 {
		return nil, ErrLogoUnreadable // trailing bytes after IEND
	}
	// The JPEG decoder reads ahead, so trailing bytes cannot be seen from the reader: walk the marker structure to
	// the REAL first EOI and require it to be the end of the input (repair B2).
	if format == "jpeg" {
		if end, ok := jpegStreamEnd(raw); !ok || end != len(raw) {
			return nil, ErrLogoUnreadable
		}
	}
	b := img.Bounds()
	if format == "gif" {
		if b.Min.X < 0 || b.Min.Y < 0 || b.Max.X > cfg.Width || b.Max.Y > cfg.Height || b.Dx() <= 0 || b.Dy() <= 0 {
			return nil, ErrLogoUnreadable
		}
	} else if b.Min.X != 0 || b.Min.Y != 0 || b.Dx() != cfg.Width || b.Dy() != cfg.Height {
		return nil, ErrLogoUnreadable
	}

	out, err := encodeScaledPNG(img)
	if err != nil {
		return nil, err
	}
	if len(out) > LogoMaxOutputBytes {
		return nil, ErrLogoTooBigOutput
	}
	return out, nil
}

// jpegStreamEnd walks a JPEG's marker segments and entropy-coded scans from SOI and returns the offset just past
// the FIRST EOI that ends the stream. A 0xFF in scan data is a marker only when the next byte is neither 0x00
// (stuffing), 0xFF (fill) nor RSTn; every other marker ends the scan and is parsed by the walk. Bytes after that
// EOI (garbage, a second image, a spurious FF D9) are therefore never mistaken for the end.
func jpegStreamEnd(b []byte) (int, bool) {
	if len(b) < 4 || b[0] != 0xFF || b[1] != 0xD8 {
		return 0, false
	}
	i := 2
	for i < len(b) {
		if b[i] != 0xFF {
			return 0, false
		}
		for i < len(b) && b[i] == 0xFF { // fill bytes
			i++
		}
		if i >= len(b) {
			return 0, false
		}
		m := b[i]
		i++
		switch {
		case m == 0xD9:
			return i, true
		case m == 0x00 || m == 0x01 || (m >= 0xD0 && m <= 0xD8):
			continue // no length (stuffing is invalid here, RSTn/SOI/TEM carry none)
		}
		if i+2 > len(b) {
			return 0, false
		}
		n := int(b[i])<<8 | int(b[i+1])
		if n < 2 || i+n > len(b) {
			return 0, false
		}
		i += n
		if m == 0xDA { // SOS: entropy-coded data follows until the next real marker
			for i < len(b) {
				if b[i] != 0xFF {
					i++
					continue
				}
				// A run of FF fill bytes may precede the byte that decides what this is (FF FF D0 is a fill byte then
				// RST0). Consume the whole run first, then classify (repair r2-1).
				j := i
				for j < len(b) && b[j] == 0xFF {
					j++
				}
				if j >= len(b) {
					return 0, false
				}
				if nx := b[j]; nx == 0x00 || (nx >= 0xD0 && nx <= 0xD7) {
					i = j + 1 // FF00 is stuffed data, RSTn resumes the entropy data
					continue
				}
				i = j - 1 // any other marker ends the scan: leave i on its FF prefix for the outer loop
				break
			}
		}
	}
	return 0, false
}

// encodeScaledPNG scales img down into the 512x256 box (never up), preserving aspect and alpha, and encodes it.
func encodeScaledPNG(img image.Image) ([]byte, error) {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	tw, th := w, h
	if w > LogoBoxW || h > LogoBoxH {
		f := math.Min(float64(LogoBoxW)/float64(w), float64(LogoBoxH)/float64(h))
		tw, th = int(math.Max(1, math.Floor(float64(w)*f))), int(math.Max(1, math.Floor(float64(h)*f)))
	}
	// Premultiplied RGBA working copy (a GIF frame is a sub-rectangle: draw handles the offset).
	src := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(src, src.Bounds(), img, b.Min, draw.Src)
	dst := image.NewNRGBA(image.Rect(0, 0, tw, th))
	if tw == w && th == h {
		draw.Draw(dst, dst.Bounds(), src, image.Point{}, draw.Src)
	} else {
		boxScale(dst, src)
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, dst); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// boxScale area-averages the premultiplied src into the (smaller) dst.
func boxScale(dst *image.NRGBA, src *image.RGBA) {
	sw, sh := src.Bounds().Dx(), src.Bounds().Dy()
	dw, dh := dst.Bounds().Dx(), dst.Bounds().Dy()
	for y := 0; y < dh; y++ {
		y0, y1 := y*sh/dh, (y+1)*sh/dh
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < dw; x++ {
			x0, x1 := x*sw/dw, (x+1)*sw/dw
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, bl, a, n uint64
			for yy := y0; yy < y1; yy++ {
				row := src.Pix[yy*src.Stride:]
				for xx := x0; xx < x1; xx++ {
					p := row[xx*4 : xx*4+4]
					r += uint64(p[0])
					g += uint64(p[1])
					bl += uint64(p[2])
					a += uint64(p[3])
					n++
				}
			}
			c := color.RGBA{R: uint8(r / n), G: uint8(g / n), B: uint8(bl / n), A: uint8(a / n)}
			dst.SetNRGBA(x, y, color.NRGBAModel.Convert(c).(color.NRGBA))
		}
	}
}

// VerifyConvertedLogo is the PARENT's re-check of the child's output before anything is stored: a valid PNG
// inside the box, at most 64 KiB, nothing after IEND.
func VerifyConvertedLogo(out []byte) error {
	if len(out) == 0 || len(out) > LogoMaxOutputBytes || !bytes.HasPrefix(out, logoPNGMagic) {
		return errors.New("logo conversion produced an unusable image")
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(out))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > LogoBoxW || cfg.Height > LogoBoxH {
		return errors.New("logo conversion produced an unusable image")
	}
	rd := bytes.NewReader(out)
	if _, err := png.Decode(rd); err != nil || rd.Len() != 0 {
		return errors.New("logo conversion produced an unusable image")
	}
	return nil
}

// readLimited reads at most max bytes and reports whether the source had more.
func readLimited(r io.Reader, max int) ([]byte, bool, error) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, false, err
	}
	if len(buf) > max {
		return buf[:max], true, nil
	}
	return buf, false, nil
}

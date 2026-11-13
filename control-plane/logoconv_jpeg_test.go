package controlplane

// Hand-built JPEGs for the stream-end walk (repair B2 and r2-1). Go's encoder emits neither restart markers nor
// progressive scans, so the fixtures are assembled byte by byte from tiny Huffman tables (DC: one 2-bit code for
// category 0; AC: one 4-bit code for EOB), which keeps every entropy byte checkable by eye.

import (
	"bytes"
	"image/jpeg"
	"testing"
)

func jseg(marker byte, payload ...byte) []byte {
	n := len(payload) + 2
	return append([]byte{0xFF, marker, byte(n >> 8), byte(n)}, payload...)
}

func jdht(class byte, lengthWithOneCode int) []byte {
	p := []byte{class}
	counts := make([]byte, 16)
	counts[lengthWithOneCode-1] = 1
	p = append(p, counts...)
	return jseg(0xC4, append(p, 0x00)...)
}

func jdqt() []byte { return jseg(0xDB, append([]byte{0x00}, bytes.Repeat([]byte{1}, 64)...)...) }

// restartJPEG is a 16x8 greyscale baseline JPEG with a restart interval of one MCU: two MCUs, an RST0 between them.
// betweenMCUs is the bytes placed between the two entropy bytes (FF D0, or FF FF D0 with a fill byte).
func restartJPEG(betweenMCUs ...byte) []byte {
	out := []byte{0xFF, 0xD8}
	out = append(out, jdqt()...)
	out = append(out, jseg(0xC0, 8, 0x00, 0x08, 0x00, 0x10, 1, 1, 0x11, 0)...)
	out = append(out, jdht(0x00, 2)...)
	out = append(out, jdht(0x10, 4)...)
	out = append(out, jseg(0xDD, 0x00, 0x01)...)
	out = append(out, jseg(0xDA, 1, 1, 0x00, 0, 63, 0)...)
	out = append(out, 0x03) // MCU 1: DC category 0 ("00"), EOB ("0000"), padded with ones
	out = append(out, betweenMCUs...)
	out = append(out, 0x03) // MCU 2
	return append(out, 0xFF, 0xD9)
}

// progressiveJPEG is an 8x8 greyscale progressive JPEG with TWO scans (DC first, then AC first).
func progressiveJPEG() []byte {
	out := []byte{0xFF, 0xD8}
	out = append(out, jdqt()...)
	out = append(out, jseg(0xC2, 8, 0x00, 0x08, 0x00, 0x08, 1, 1, 0x11, 0)...)
	out = append(out, jdht(0x00, 2)...)
	out = append(out, jseg(0xDA, 1, 1, 0x00, 0, 0, 0x00)...) // scan 1: DC, Ss=0 Se=0
	out = append(out, 0x3F)                                  // DC category 0 ("00") padded with ones
	out = append(out, jdht(0x10, 4)...)
	out = append(out, jseg(0xDA, 1, 1, 0x00, 1, 63, 0x00)...) // scan 2: AC, Ss=1 Se=63
	out = append(out, 0x0F)                                   // EOB ("0000") padded with ones
	return append(out, 0xFF, 0xD9)
}

func TestHandBuiltJPEGsAreRealJPEGsToGo(t *testing.T) {
	for name, raw := range map[string][]byte{
		"restart (RST0 between MCUs)": restartJPEG(0xFF, 0xD0),
		"progressive (two scans)":     progressiveJPEG(),
	} {
		if _, err := jpeg.Decode(bytes.NewReader(raw)); err != nil {
			t.Fatalf("fixture %q is not a JPEG Go accepts: %v", name, err)
		}
	}
}

func TestJPEGWalkAcceptsRestartIntervalsFillBytesAndProgressiveScans(t *testing.T) {
	for name, raw := range map[string][]byte{
		"restart":                        restartJPEG(0xFF, 0xD0),
		"restart with a fill byte":       restartJPEG(0xFF, 0xFF, 0xD0),
		"restart with three fills":       restartJPEG(0xFF, 0xFF, 0xFF, 0xFF, 0xD0),
		"progressive":                    progressiveJPEG(),
		"fill then stuffed zero in data": restartJPEG(0xFF, 0xFF, 0x00),
	} {
		end, ok := jpegStreamEnd(raw)
		if !ok || end != len(raw) {
			t.Errorf("%s: walk end=%d ok=%v len=%d", name, end, ok, len(raw))
		}
	}
}

// What the CONVERTER does must agree with Go's decoder: a restart JPEG (and a progressive one) converts; a variant
// Go's own decoder rejects is rejected by the decode step, never by a wrong verdict of the walk.
func TestConverterAcceptsRestartAndProgressiveJPEGs(t *testing.T) {
	for name, raw := range map[string][]byte{"restart": restartJPEG(0xFF, 0xD0), "progressive": progressiveJPEG()} {
		out, err := ConvertLogo(raw)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if err := VerifyConvertedLogo(out); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	withFill := restartJPEG(0xFF, 0xFF, 0xD0)
	_, goErr := jpeg.Decode(bytes.NewReader(withFill))
	_, convErr := ConvertLogo(withFill)
	if (goErr == nil) != (convErr == nil) {
		t.Errorf("fill before RST: Go decoder err=%v, converter err=%v (they must agree)", goErr, convErr)
	}
}

func TestJPEGTrailingDataStillRefusedAfterRestartAndProgressiveStreams(t *testing.T) {
	for name, raw := range map[string][]byte{"restart": restartJPEG(0xFF, 0xD0), "progressive": progressiveJPEG()} {
		wantLogoErr(t, name+" + garbage", append(append([]byte(nil), raw...), 'x', 'y'), ErrLogoUnreadable)
		wantLogoErr(t, name+" + garbage + FF D9", append(append([]byte(nil), raw...), 'x', 0xFF, 0xD9), ErrLogoUnreadable)
		wantLogoErr(t, name+" doubled", append(append([]byte(nil), raw...), raw...), ErrLogoUnreadable)
		wantLogoErr(t, name+" + FF D9", append(append([]byte(nil), raw...), 0xFF, 0xD9), ErrLogoUnreadable)
	}
}

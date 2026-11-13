package controlplane

// Golden vectors for the accent contrast gate, shared with the console (docs/66 2j). The same JSON file is read by
// web/viewer/src/lib/brand_contrast.test.ts, so the server's formula and the console's inline readout cannot drift
// apart: change a constant or the formula on one side and the other side's test fails against the file.

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

type contrastVectors struct {
	Constants struct {
		LabelBackground string  `json:"label_background"`
		Surface         string  `json:"surface"`
		LabelMin        float64 `json:"label_min"`
		SurfaceMin      float64 `json:"surface_min"`
	} `json:"constants"`
	Ratios []struct {
		A     string  `json:"a"`
		B     string  `json:"b"`
		Ratio float64 `json:"ratio"`
	} `json:"ratios"`
	Accents []struct {
		Input      string `json:"input"`
		OK         bool   `json:"ok"`
		Normalized string `json:"normalized"`
		Error      string `json:"error"`
	} `json:"accents"`
}

func loadContrastVectors(t *testing.T) contrastVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/brand_contrast_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v contrastVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Ratios) < 10 || len(v.Accents) < 15 {
		t.Fatalf("vector file looks truncated: %d ratios, %d accents", len(v.Ratios), len(v.Accents))
	}
	return v
}

func TestContrastGoldenConstants(t *testing.T) {
	v := loadContrastVectors(t)
	if v.Constants.LabelBackground != ContrastLabelBackground || v.Constants.Surface != ContrastSurface ||
		v.Constants.LabelMin != ContrastLabelMin || v.Constants.SurfaceMin != ContrastSurfaceMin {
		t.Fatalf("golden constants %+v differ from the server's (%s %.1f, %s %.1f)", v.Constants,
			ContrastLabelBackground, ContrastLabelMin, ContrastSurface, ContrastSurfaceMin)
	}
}

func TestContrastGoldenRatios(t *testing.T) {
	for _, c := range loadContrastVectors(t).Ratios {
		got, ok := ContrastRatio(c.A, c.B)
		if !ok || math.Abs(got-c.Ratio) > 0.00005 {
			t.Errorf("ContrastRatio(%s, %s) = %.6f, golden %.4f", c.A, c.B, got, c.Ratio)
		}
		if back, _ := ContrastRatio(c.B, c.A); back != got {
			t.Errorf("ContrastRatio is not symmetric for %s, %s", c.A, c.B)
		}
	}
}

func TestContrastGoldenAccents(t *testing.T) {
	for _, c := range loadContrastVectors(t).Accents {
		got, ferr := NormalizeBrandAccent(c.Input)
		if c.OK {
			if ferr != nil || got != c.Normalized {
				t.Errorf("accent %q: got (%q, %v), golden accepts as %q", c.Input, got, ferr, c.Normalized)
			}
			continue
		}
		if ferr == nil || ferr.Field != "accent_color" || ferr.Msg != c.Error {
			t.Errorf("accent %q: got (%q, %v), golden refuses with %q", c.Input, got, ferr, c.Error)
		}
	}
}

// ---- the field rules ------------------------------------------------------------------------------------

type textVector struct {
	Input      string `json:"input"`
	OK         bool   `json:"ok"`
	Normalized string `json:"normalized"`
	Error      string `json:"error"`
}

type contactVector struct {
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	OK         bool   `json:"ok"`
	Normalized struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	} `json:"normalized"`
	Error string `json:"error"`
}

func loadTextVectors(t *testing.T) (names, texts []textVector, contacts []contactVector) {
	t.Helper()
	raw, err := os.ReadFile("testdata/brand_text_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Names    []textVector    `json:"names"`
		Texts    []textVector    `json:"texts"`
		Contacts []contactVector `json:"contacts"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Names) < 20 || len(v.Texts) < 10 || len(v.Contacts) < 20 {
		t.Fatalf("vector file looks truncated: %d names, %d texts, %d contacts", len(v.Names), len(v.Texts), len(v.Contacts))
	}
	return v.Names, v.Texts, v.Contacts
}

func checkTextVectors(t *testing.T, what, field string, vs []textVector, f func(string) (string, *BrandFieldError)) {
	for _, c := range vs {
		got, ferr := f(c.Input)
		if c.OK {
			if ferr != nil || got != c.Normalized {
				t.Errorf("%s %q: got (%q, %v), golden accepts as %q", what, c.Input, got, ferr, c.Normalized)
			}
			continue
		}
		if ferr == nil || ferr.Field != field || ferr.Msg != c.Error {
			t.Errorf("%s %q: got (%q, %v), golden refuses with %q", what, c.Input, got, ferr, c.Error)
		}
	}
}

func TestBrandTextGoldenVectors(t *testing.T) {
	names, texts, contacts := loadTextVectors(t)
	checkTextVectors(t, "name", "product_name", names, NormalizeBrandName)
	checkTextVectors(t, "support text", "support_text", texts, NormalizeBrandSupportText)
	for _, c := range contacts {
		got, ferr := NormalizeBrandContact(BrandContact{Kind: c.Kind, Value: c.Value})
		if c.OK {
			if ferr != nil || got.Kind != c.Normalized.Kind || got.Value != c.Normalized.Value {
				t.Errorf("contact %q %q: got (%+v, %v), golden accepts as %+v", c.Kind, c.Value, got, ferr, c.Normalized)
			}
			continue
		}
		if ferr == nil || ferr.Field != "support_contact" || ferr.Msg != c.Error {
			t.Errorf("contact %q %q: got (%+v, %v), golden refuses with %q", c.Kind, c.Value, got, ferr, c.Error)
		}
	}
}

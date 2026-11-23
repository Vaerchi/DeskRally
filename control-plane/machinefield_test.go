package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCanonicalFieldValue(t *testing.T) {
	for _, tc := range []struct {
		typ, input, want string
		valid            bool
	}{
		{"text", " \t ", " \t ", true},
		{"text", "", "", true},
		{"number", " 007.500 ", "7.5", true},
		{"number", "000.00", "0", true},
		{"number", "-000.000001000", "-0.000001", true},
		{"number", "999999999999999.123456", "999999999999999.123456", true},
		{"number", "9999999999999999", "", false},
		{"number", "1.0000001", "", false},
		{"number", strings.Repeat("0", 63) + "1", "1", true},
		{"number", strings.Repeat("0", 64) + "1", "", false},
		{"number", "-0", "", false},
		{"number", "-00", "", false},
		{"number", "-0.000", "", false},
		{"number", "1e2", "", false},
		{"number", "1,2", "", false},
		{"number", "+1", "", false},
		{"number", "1.", "", false},
		{"number", ".1", "", false},
		{"number", "١", "", false},
		{"number", "\u00a01", "", false},
		{"number", "1\x00", "", false},
		{"number", "1\u0085", "", false},
		{"number", "1\xff", "", false},
		{"number", "", "", false},
		{"date", " 2000-02-29 ", "2000-02-29", true},
		{"date", "2024-02-29", "2024-02-29", true},
		{"date", "1900-02-29", "", false},
		{"date", "2100-02-29", "", false},
		{"date", "1900-01-01", "1900-01-01", true},
		{"date", "2999-12-31", "2999-12-31", true},
		{"date", "1899-12-31", "", false},
		{"date", "3000-01-01", "", false},
		{"date", "2024-04-31", "", false},
		{"date", "2024-00-01", "", false},
		{"date", "2024-01-00", "", false},
		{"date", "2024-1-01", "", false},
		{"date", "2024-01-01Z", "", false},
		{"boolean", " true ", "true", true},
		{"boolean", "false", "false", true},
		{"boolean", "True", "", false},
		{"boolean", "0", "", false},
		{"boolean", "false\t", "", false},
		{"boolean", " ", "", false},
		{"choice", " HQ ", "HQ", true},
		{"choice", "hq", "", false},
		{"choice", "Remote", "Remote", true},
		{"choice", "Other", "", false},
		{"choice", "", "", false},
		{"other", "ignored", "", false},
	} {
		field := MachineField{Type: tc.typ, Choices: []string{"HQ", "Remote"}}
		got, ok := canonicalFieldValue(field, tc.input)
		if ok != tc.valid || (ok && got != tc.want) {
			t.Errorf("%s %q = %q, %v, want %q, %v", tc.typ, tc.input, got, ok, tc.want, tc.valid)
		}
		if conforms := fieldValueConforms(field, tc.input); conforms != (tc.valid && tc.input == tc.want) {
			t.Errorf("%s %q conforms = %v", tc.typ, tc.input, conforms)
		}
	}
}

func TestMachineFieldDefinitionValidation(t *testing.T) {
	for _, tc := range []struct {
		key, label, typ string
		choices         []string
		valid           bool
	}{
		{"order", " Display label ", "text", nil, true},
		{"a/b", "Label", "boolean", nil, true},
		{strings.Repeat("é", 64), strings.Repeat("é", 64), "number", nil, true},
		{strings.Repeat("é", 65), "Label", "number", nil, false},
		{"r", strings.Repeat("é", 65), "date", nil, false},
		{"", "Label", "text", nil, false},
		{".", "Label", "text", nil, false},
		{"..", "Label", "text", nil, false},
		{" r", "Label", "text", nil, false},
		{"r\u00a0", "Label", "text", nil, false},
		{"r\u0085s", "Label", "text", nil, false},
		{"r\xff", "Label", "text", nil, false},
		{"r", "", "text", nil, false},
		{"r", "L\x00", "text", nil, false},
		{"r", "L\xff", "text", nil, false},
		{"r", "L", "number", []string{"x"}, false},
		{"r", "L", "invalid", nil, false},
		{"r", "L", "choice", nil, false},
		{"r", "L", "choice", make([]string, 65), false},
		{"r", "L", "choice", []string{"é", "HQ"}, true},
		{"r", "L", "choice", []string{"K", "K"}, false},
		{"r", "L", "choice", []string{"x", "X"}, false},
		{"r", "L", "choice", []string{""}, false},
		{"r", "L", "choice", []string{" x"}, false},
		{"r", "L", "choice", []string{"x "}, false},
		{"r", "L", "choice", []string{"x\u0085"}, false},
		{"r", "L", "choice", []string{"x\xff"}, false},
		{"r", "L", "choice", []string{strings.Repeat("x", 129)}, false},
	} {
		field := MachineField{Key: tc.key, Label: tc.label, Type: tc.typ, Choices: tc.choices}
		if got := validMachineField(field); got != tc.valid {
			t.Errorf("%+v validation = %v, want %v", field, got, tc.valid)
		}
	}
}

func TestMachineFieldManagementBodyLimit(t *testing.T) {
	tenant := "tenant-123"
	p := &Principal{TenantID: tenant, UserID: "u1", Grant: NewGrant("u1", tenant, NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(p)
	h := srv.Handler()
	cases := []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/machine-fields", `{"key":"first","label":"First","type":"number"}`, 201},
		{"PUT", "/machine-fields/first", `{"label":"First","type":"number"}`, 400},
		{"PUT", "/machine-field-order", `{"order_revision":1,"keys":["first"]}`, 200},
	}
	for _, tc := range cases {
		body := strings.Repeat(" ", maxSmallJSONBodyBytes-len(tc.body)) + tc.body
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(" "+body)))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("%s %s over limit = %d, want 413", tc.method, tc.path, rec.Code)
		}
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(body)))
		if rec.Code != tc.want {
			t.Fatalf("%s %s at limit = %d, want %d: %s", tc.method, tc.path, rec.Code, tc.want, rec.Body)
		}
	}
}

func TestInMemoryMachineFieldsAndPropertyEdits(t *testing.T) {
	const tenant = "tenant-123"
	p := &Principal{TenantID: tenant, UserID: "u1", Grant: NewGrant("u1", tenant, NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(p)
	h := srv.Handler()
	do := func(method, path, body string, status int) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		if rec.Code != status {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, rec.Code, status, rec.Body)
		}
		return rec
	}
	ctx := context.Background()
	machine := &Machine{DeviceID: "fields-device", GroupID: DevDefaultMachineGroupID, Name: "Field machine"}
	if err := srv.Machines.EnrollMachine(ctx, tenant, machine); err != nil {
		t.Fatal(err)
	}
	property := "/machines/" + machine.ID + "/properties/n"
	do("PUT", property, `{"value":"1.00"}`, 200)
	do("POST", "/machine-fields", `{"key":"n","label":"N","type":"number"}`, 201)
	reportPath := "/machine-fields/n/nonconforming"
	var report machineFieldReport
	rec := do("GET", reportPath, "", 200)
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil || report.Total != 1 ||
		len(report.Machines) != 1 || report.Machines[0].Value != "1.00" {
		t.Fatalf("report = %+v, %v", report, err)
	}
	do("PUT", property, `{"value":"`+"\xff"+`"}`, 400)
	rec = do("PUT", property, `{"value":" 007.50 "}`, 200)
	if !strings.Contains(rec.Body.String(), `"value":"7.5"`) {
		t.Fatalf("noncanonical response: %s", rec.Body)
	}
	rec = do("GET", reportPath, "", 200)
	if !strings.Contains(rec.Body.String(), `"total":0`) {
		t.Fatalf("canonical value is nonconforming: %s", rec.Body)
	}
	do("DELETE", property, "", 200)

	do("POST", "/machine-fields", `{"key":"\uD800","label":"Bad","type":"text"}`, 400)
	do("POST", "/machine-fields", `{"key":"bad","label":"\uDC00","type":"text"}`, 400)
	do("POST", "/machine-fields", `{"key":"bad","label":"Bad","type":"choice","choices":["\uD800"]}`, 400)
	do("POST", "/machine-fields", `{"key":"choice","label":"Choice","type":"choice","choices":["�","\uD83D\uDE00","\\uD800"]}`, 201)
	do("POST", "/machine-fields", `{"key":"text","label":"Text","type":"text"}`, 201)
	for _, tc := range []struct {
		key, value string
		status     int
	}{
		{"choice", `"\uD800"`, 400},
		{"choice", `"\uDC00"`, 400},
		{"choice", `"�"`, 200},
		{"choice", `"\uD83D\uDE00"`, 200},
		{"choice", `"\\uD800"`, 200},
		{"text", `"\uD800"`, 200},
		{"undefined", `"\uD800"`, 200},
	} {
		rec = do("PUT", "/machines/"+machine.ID+"/properties/"+tc.key, `{"value":`+tc.value+`}`, tc.status)
		if tc.key != "choice" && !strings.Contains(rec.Body.String(), `"value":"�"`) {
			t.Fatalf("legacy decoder response for %s: %s", tc.key, rec.Body)
		}
	}
	do("POST", "/machines/bulk-property",
		`{"machine_ids":["`+machine.ID+`"],"key":"choice","value":"\uD800"}`, 400)
}

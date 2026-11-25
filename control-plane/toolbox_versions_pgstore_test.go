package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

type tbVersions struct {
	Versions []ToolboxVersion `json:"versions"`
}

func TestPgToolboxVersionHistory(t *testing.T) {
	f := newToolboxFixture(t)
	ctx := context.Background()

	code, it := tbCreate(t, f.ownerSrv, "shared", "Maintenance/Clear temp", "powershell", "Remove-Item $env:TEMP\\* -Recurse")
	if code != http.StatusCreated {
		t.Fatalf("create = %d", code)
	}
	if c := tbUpdate(t, f.ownerSrv, it.ID, 1, "Maintenance/Clear temp", map[string]any{"body": "Get-ChildItem $env:TEMP"}); c != http.StatusOK {
		t.Fatalf("update 1 = %d", c)
	}
	if c := tbUpdate(t, f.ownerSrv, it.ID, 2, "Maintenance/Clear temp v3", nil); c != http.StatusOK {
		t.Fatalf("update 2 = %d", c)
	}

	var got tbVersions
	if c := apiJSON(t, f.ownerSrv, "GET", "/toolbox/"+it.ID+"/versions", "", &got); c != http.StatusOK {
		t.Fatalf("versions = %d", c)
	}
	if len(got.Versions) != 3 {
		t.Fatalf("versions = %+v, want 3", got.Versions)
	}
	// Newest first; each row is exactly what was saved, with who saved it.
	v3, v2, v1 := got.Versions[0], got.Versions[1], got.Versions[2]
	if v3.Version != 3 || v3.Name != "Maintenance/Clear temp v3" || v3.Body != "Get-Date" ||
		v2.Version != 2 || v2.Body != "Get-ChildItem $env:TEMP" ||
		v1.Version != 1 || v1.Body != "Remove-Item $env:TEMP\\* -Recurse" || v1.BodySHA256 != ToolboxBodySHA256(v1.Body) {
		t.Fatalf("history = %+v", got.Versions)
	}
	if v1.SavedBy != "owner@acme.test" {
		t.Fatalf("saved_by = %q", v1.SavedBy)
	}

	// The technician sees a shared item's history; nobody sees another user's personal item or another tenant's.
	if c := apiJSON(t, f.techSrv, "GET", "/toolbox/"+it.ID+"/versions", "", nil); c != http.StatusOK {
		t.Fatalf("technician reading shared history = %d", c)
	}
	_, mine := tbCreate(t, f.techSrv, "personal", "Mine", "cmd", "whoami")
	if c := apiJSON(t, f.ownerSrv, "GET", "/toolbox/"+mine.ID+"/versions", "", nil); c != http.StatusNotFound {
		t.Fatalf("another user's personal history = %d, want 404", c)
	}
	if c := apiJSON(t, f.alienSrv, "GET", "/toolbox/"+it.ID+"/versions", "", nil); c != http.StatusNotFound {
		t.Fatalf("cross-tenant history = %d, want 404", c)
	}

	// Pruned to the newest maxToolboxVersionsKept.
	ver := int64(3)
	for i := 0; i < maxToolboxVersionsKept; i++ {
		if c := tbUpdate(t, f.ownerSrv, it.ID, ver, "Maintenance/Clear temp v3", map[string]any{"body": fmt.Sprintf("Write-Output %d", i)}); c != http.StatusOK {
			t.Fatalf("update %d = %d", i, c)
		}
		ver++
	}
	got = tbVersions{}
	apiJSON(t, f.ownerSrv, "GET", "/toolbox/"+it.ID+"/versions", "", &got)
	if len(got.Versions) != maxToolboxVersionsKept || got.Versions[0].Version != ver || got.Versions[len(got.Versions)-1].Version != ver-maxToolboxVersionsKept+1 {
		t.Fatalf("after pruning: %d rows, newest %d, oldest %d", len(got.Versions), got.Versions[0].Version, got.Versions[len(got.Versions)-1].Version)
	}

	// Deleting the item deletes its history.
	if c := apiJSON(t, f.ownerSrv, "DELETE", fmt.Sprintf("/toolbox/%s?expected_version=%d", it.ID, ver), "", nil); c != http.StatusNoContent {
		t.Fatalf("delete = %d", c)
	}
	var n int
	if err := f.su.QueryRow(ctx, `SELECT count(*) FROM toolbox_item_version WHERE item_id = $1`, it.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("history rows after delete = %d (%v)", n, err)
	}
}

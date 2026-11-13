package controlplane

import (
	"context"
	"sync"
	"time"
)

// fakePlatformStore lets the HTTP handler tests reach /platform/* without Postgres. It is NOT a model
// of the authorization (that lives in the DB functions and is tested in platform_pgstore_test.go): it
// records what the handlers passed and returns whatever the test configured.
type fakePlatformStore struct {
	mu          sync.Mutex
	err         error // returned by every call when set
	tenants     []PlatformTenant
	created     []string // slugs
	suspended   []string // "<id>:<bool>:<reason>"
	callers     []PlatformCaller
	reach       []ReachRow
	reachRanges []string
}

func (f *fakePlatformStore) record(c PlatformCaller) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callers = append(f.callers, c)
}

func (f *fakePlatformStore) Whoami(_ context.Context, c PlatformCaller) (PlatformWhoami, error) {
	f.record(c)
	if f.err != nil {
		return PlatformWhoami{}, f.err
	}
	return PlatformWhoami{Operator: true, MFAOK: true, MFAFresh: true}, nil
}

func (f *fakePlatformStore) ListTenants(_ context.Context, c PlatformCaller) ([]PlatformTenant, error) {
	f.record(c)
	if f.err != nil {
		return nil, f.err
	}
	return f.tenants, nil
}

func (f *fakePlatformStore) CreateTenant(_ context.Context, c PlatformCaller, slug, name, mode, _ string) (*Tenant, error) {
	f.record(c)
	if f.err != nil {
		return nil, f.err
	}
	f.mu.Lock()
	f.created = append(f.created, slug)
	f.mu.Unlock()
	return &Tenant{ID: newUUID(), Slug: slug, Name: name, DeploymentMode: mode, CreatedAt: time.Now()}, nil
}

func (f *fakePlatformStore) SetSuspended(_ context.Context, c PlatformCaller, id string, suspended bool, reason, _ string) (*Tenant, error) {
	f.record(c)
	if f.err != nil {
		return nil, f.err
	}
	f.mu.Lock()
	f.suspended = append(f.suspended, id+":"+map[bool]string{true: "true", false: "false"}[suspended]+":"+reason)
	f.mu.Unlock()
	return &Tenant{ID: id, Disabled: suspended}, nil
}

func (f *fakePlatformStore) DownloadReport(_ context.Context, c PlatformCaller, from, to time.Time, _ string) ([]ReachRow, error) {
	f.record(c)
	if f.err != nil {
		return nil, f.err
	}
	f.mu.Lock()
	f.reachRanges = append(f.reachRanges, from.Format("2006-01-02")+".."+to.Format("2006-01-02"))
	f.mu.Unlock()
	return f.reach, nil
}

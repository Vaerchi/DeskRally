package controlplane

// Test-only accessors for the admission pool's peak watermark (docs/66 release gate, step 5). Production code only
// ever writes the marks (in Acquire); reading and resetting them exists solely here.

// peak reports the highest global in-flight count and the highest in-flight count of any single key seen since the
// pool was built or last reset.
func (p *admissionPool) peak() (global, perKey int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peakGlobal, p.peakPerKey
}

// resetPeak restarts the marks at the CURRENT load, so a phase that begins with requests in flight does not
// under-report.
func (p *admissionPool) resetPeak() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.peakGlobal = p.inflight
	p.peakPerKey = 0
	for _, n := range p.perKey {
		p.peakPerKey = max(p.peakPerKey, n)
	}
}

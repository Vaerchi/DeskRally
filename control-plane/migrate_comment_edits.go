package controlplane

// reviewedCommentOnlyEdits lists applied migrations whose file was later edited in SQL COMMENTS ONLY, by exact
// before/after sha256, so the drift check (migrate.go) accepts precisely that edit and nothing else. Any other
// difference, including a further edit to one of these files, is still refused.
//
// 2026-11-23: a personal name was removed from one comment line in each file below (an external PII scan of the
// public repository). The statements are byte-identical; reviewed with `git diff 92e11b37 -- control-plane/migrations`.
// Add an entry only for a reviewed comment-only change; never to get past a schema edit.
var reviewedCommentOnlyEdits = map[string]struct{ from, to string }{
	"0080_oidc_remember.sql": {
		from: "e255fbb32e6a5759478821b020d90d71cd814324da5d33f15d9e00f5777f6ceb",
		to:   "1febe33ca7bcd68bd5d2808e8be9d836159915a23444b555a525af4f3c4c0058",
	},
	"0083_tenant_session_binding.sql": {
		from: "f1a21c6109c4eabb3d4cdf2355ca8fc21d0267b332e91ab55aef5967ae41e26a",
		to:   "3f86c01f78eff5896a0eedd2ce7b48688ae15fda0daf1b6427052f3d153a60e7",
	},
}

// isReviewedCommentOnlyEdit reports whether an applied migration recorded as `recorded` may be on disk as `onDisk`.
func isReviewedCommentOnlyEdit(name, recorded, onDisk string) bool {
	e, ok := reviewedCommentOnlyEdits[name]
	return ok && recorded == e.from && onDisk == e.to
}

package controlplane

import "net/http"

// GET /agent-version — returns the operator-configured expected agent version.
//
// Any authenticated principal with CapViewMachines may read this. The endpoint
// is used by the console MachinesPanel to flag machines that are running a
// different build than the one the operator has designated as current.
//
// When PublishedAgentVersion is empty ("not configured"), the response carries
// configured=false and no version key. The console treats that state as
// "version tracking not enabled" and shows no mismatch badges.
//
// SCOPE: PublishedAgentVersion is a DEPLOYMENT-LEVEL value — a single string
// for the whole CP process, not per-tenant. This is appropriate for self-hosted
// single-tenant deployments where one operator controls all agents. A multi-tenant
// SaaS deployment that needs per-tenant version targets would require a migration
// adding published_agent_version to the tenant table and routing through TenantStore.
//
// This is the CP side of the agent auto-update story (docs/01 §6 "Agent
// auto-update"). Step 1 (machine.agent_version tracking) already shipped in
// migration 0039. This endpoint is step 2: giving the console a target to
// compare against. Step 3 (the agent polling and self-updating) is a
// subsequent round.

type agentVersionResponse struct {
	Version    string `json:"version,omitempty"`
	Configured bool   `json:"configured"`
}

func (s *Server) handleGetAgentVersion(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewMachines); err != nil {
		writeDenied(w, err)
		return
	}
	resp := agentVersionResponse{Configured: s.PublishedAgentVersion != ""}
	if s.PublishedAgentVersion != "" {
		resp.Version = s.PublishedAgentVersion
	}
	writeJSON(w, http.StatusOK, resp)
}

package controlplane

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// pathParamNames extracts the {name} placeholders of a route path, in order.
func pathParamNames(path string) []string {
	var names []string
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") && len(seg) > 2 {
			names = append(names, seg[1:len(seg)-1])
		}
	}
	return names
}

// Public, versioned HTTP API (docs/01 §7 P1 "Public HTTP API"; writes + schemas: docs/59).
//
// This file adds nothing to the authorization model. It mounts a VERSIONED alias (/api/v1/…) of a
// slice of the existing management handlers — fleet reads AND, since docs/59, the fleet WRITE
// operations (machine-group CRUD, machine moves, machine properties) — on the SAME auth → tenant
// (RLS) → capability chain the console uses, and serves an OpenAPI document that is GENERATED from
// the same route table — so the published contract can neither describe a route that is not mounted
// nor omit one that is. Every route gates on a capability in apiTokenGrantableCaps (apitoken.go), so
// an API token can actually call it; interactive-session creation and user management are
// deliberately absent, because they require a real accountable human (see apitoken.go's note on the
// closed set). The exact (method, path, operationId, capability) surface is PINNED by an
// independently-maintained table in publicapi_test.go — growing this file alone cannot grow the
// contract unnoticed.

// PublicAPIVersion is the one version segment of the public API. It is BOTH the path prefix (/api/v1)
// and the advertised version; changing it is a deliberate breaking-change act, not a silent edit.
const PublicAPIVersion = "v1"

// publicAPIBasePath is where the versioned public surface is mounted.
const publicAPIBasePath = "/api/" + PublicAPIVersion

// publicAPIRoute declares ONE route. The slice below is the single source of truth: it both
// registers the route (dispatching to the SAME *Server handler the console uses) and generates the
// OpenAPI document. handler is a selector — it returns the method value so the table stays a pure
// declaration and binds to a concrete *Server only at registration.
type publicAPIRoute struct {
	// Method is GET for the read surface. docs/59 added the fleet WRITE surface (POST/PATCH/PUT/
	// DELETE); a test pins the exact method+path set and that every non-GET carries a manage_*
	// capability a token may hold — the surface cannot silently grow in either direction.
	Method      string
	Path        string // relative to publicAPIBasePath, e.g. "/machines" or "/machines/{id}".
	OperationID string // stable id for client/code generators.
	Summary     string // one line.
	Description string // what it returns and how it is scoped.
	Capability  Capability
	ResponseKey string // the top-level JSON key the success body wraps its payload in.
	// SuccessStatus is the success code the aliased handler writes; 0 means 200.
	SuccessStatus int
	// RequestSchema documents the JSON request body (OpenAPI schema object); nil = no request body.
	RequestSchema map[string]any
	// SuccessSchema documents the success body. Every route sets it, at minimum typing the envelope
	// (the named key and whether it holds an object or an array); write payloads are typed fully.
	// Row objects inside the read lists stay generic for now — refining them later is additive.
	SuccessSchema map[string]any
	// ExtraResponses documents route-specific non-success statuses (e.g. 409 on delete-in-use).
	ExtraResponses map[int]string
	// OwnAuditCaveat: the row's Description carries its OWN audit-failure/retry semantics, so the
	// generated per-write committed-then-500 sentence is suppressed (bulk-group answers 200 with an
	// item-level "could not record audit" error instead of a 500 - review f8e839aa F1).
	OwnAuditCaveat bool
	handler        func(*Server) http.HandlerFunc
}

// Small schema constructors so the table reads as a contract, not as nested map noise.
func schemaStr(desc string) map[string]any {
	s := map[string]any{"type": "string"}
	if desc != "" {
		s["description"] = desc
	}
	return s
}

func schemaObj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		req := make([]any, 0, len(required))
		for _, r := range required {
			req = append(req, r)
		}
		s["required"] = req
	}
	return s
}

// schemaNullableStr is a string schema that may also be null (OpenAPI 3.1: a type list).
func schemaNullableStr(desc string) map[string]any {
	s := map[string]any{"type": []any{"string", "null"}}
	if desc != "" {
		s["description"] = desc
	}
	return s
}

func schemaArr(items map[string]any) map[string]any {
	return map[string]any{"type": "array", "items": items}
}

// schemaEnvelope types the success wrapper: {"<key>": <inner>}, with the key required.
func schemaEnvelope(key string, inner map[string]any) map[string]any {
	return schemaObj(map[string]any{key: inner}, key)
}

// publicAPIRoutes is the public surface: the fleet reads, and (docs/59) the fleet writes. Every
// Capability here is in apiTokenGrantableCaps, every row aliases the SAME console handler (whose
// validation, group-scoped authorization and audit it inherits), and the exact surface is pinned
// by publicapi_test.go. Writes record a mgmt-audit event with the caller (for a token, the token
// id) as the actor BEFORE answering; if that audit write fails after the mutation committed, the
// response is a 500 even though the change persisted - the generated spec says so per operation.
func publicAPIRoutes() []publicAPIRoute {
	return []publicAPIRoute{
		{
			Method: "GET", Path: "/machines", OperationID: "listMachines",
			Summary:     "List machines",
			Description: "Machines in the caller's tenant visible to its view_machines capability, with derived presence. Row-level security confines the result to the token's tenant.",
			Capability:  CapViewMachines, ResponseKey: "machines",
			SuccessSchema: schemaEnvelope("machines", schemaArr(map[string]any{"type": "object"})),
			handler: func(s *Server) http.HandlerFunc { return s.handleListMachines },
		},
		{
			Method: "GET", Path: "/machines/{id}", OperationID: "getMachine",
			Summary:     "Get one machine",
			Description: "A single machine by its primary key (the id returned by listMachines). view_machines is enforced against the machine's real group, resolved from the store.",
			Capability:  CapViewMachines, ResponseKey: "machine",
			SuccessSchema: schemaEnvelope("machine", map[string]any{"type": "object"}),
			handler: func(s *Server) http.HandlerFunc { return s.handleGetMachine },
		},
		{
			Method: "GET", Path: "/machine-groups", OperationID: "listMachineGroups",
			Summary:     "List machine groups",
			Description: "Machine groups the caller may view, each with its parent_id (null for a root group, and null when the parent is not visible to the caller; an API token is tenant-wide and sees the full tree). Confined by RLS to the token's tenant.",
			Capability:  CapViewMachines, ResponseKey: "machine_groups",
			SuccessSchema: schemaEnvelope("machine_groups", schemaArr(map[string]any{"type": "object"})),
			handler: func(s *Server) http.HandlerFunc { return s.handleListMachineGroups },
		},
		{
			Method: "GET", Path: "/sessions", OperationID: "listSessions",
			Summary:     "List sessions",
			Description: "Session records in the caller's tenant visible to its view_sessions capability.",
			Capability:  CapViewSessions, ResponseKey: "sessions",
			SuccessSchema: schemaEnvelope("sessions", schemaArr(map[string]any{"type": "object"})),
			handler: func(s *Server) http.HandlerFunc { return s.handleListSessions },
		},
		{
			Method: "GET", Path: "/audit", OperationID: "listAudit",
			Summary:     "List management audit events",
			Description: "The tenant's hash-chained management audit trail. Requires view_audit.",
			Capability:  CapViewAudit, ResponseKey: "events",
			SuccessSchema: schemaEnvelope("events", schemaArr(map[string]any{"type": "object"})),
			handler: func(s *Server) http.HandlerFunc { return s.handleListAudit },
		},
		{
			Method: "GET", Path: "/audit/summary", OperationID: "auditSummary",
			Summary:     "Summarize audit events",
			Description: "Aggregate counts over the tenant's management audit trail. Requires view_audit.",
			Capability:  CapViewAudit, ResponseKey: "summary",
			SuccessSchema: schemaEnvelope("summary", map[string]any{"type": "object"}),
			handler: func(s *Server) http.HandlerFunc { return s.handleAuditSummary },
		},
		{
			Method: "POST", Path: "/machine-groups", OperationID: "createMachineGroup",
			Summary:     "Create a machine group",
			Description: "Creates a machine group with the given name (1 to 128 characters, no control characters), at the top level or - with the optional parent_id - as a subgroup of that group. Groups nest at most 4 levels (a root is level 1); an unknown parent or a result deeper than 4 levels answers 409. Requires manage_groups. NOT idempotent: names are not unique, so retrying a create that answered 500 after the mutation committed can make a duplicate group.",
			Capability:  CapManageGroups, ResponseKey: "machine_group", SuccessStatus: http.StatusCreated,
			RequestSchema: schemaObj(map[string]any{
				"name":      schemaStr("The group name, 1 to 128 characters, no control characters."),
				"parent_id": schemaNullableStr("Optional parent group id, as returned by listMachineGroups; omit or null for a top-level group."),
			}, "name"),
			SuccessSchema:  schemaEnvelope("machine_group", schemaObj(map[string]any{"id": schemaStr(""), "name": schemaStr(""), "parent_id": schemaNullableStr("")})),
			ExtraResponses: map[int]string{http.StatusConflict: "The parent group does not exist in this tenant, or the new group would nest deeper than 4 levels; nothing was created."},
			handler:        func(s *Server) http.HandlerFunc { return s.handleCreateMachineGroup },
		},
		{
			Method: "PATCH", Path: "/machine-groups/{id}", OperationID: "renameMachineGroup",
			Summary:     "Rename a machine group",
			Description: "Renames the group. Requires manage_groups. Idempotent for a given name.",
			Capability:  CapManageGroups, ResponseKey: "machine_group",
			RequestSchema: schemaObj(map[string]any{"name": schemaStr("The new name, 1 to 128 characters, no control characters.")}, "name"),
			SuccessSchema: schemaEnvelope("machine_group", schemaObj(map[string]any{"id": schemaStr(""), "name": schemaStr(""), "parent_id": schemaNullableStr("")})),
			handler:       func(s *Server) http.HandlerFunc { return s.handleRenameMachineGroup },
		},
		{
			Method: "POST", Path: "/machine-groups/{id}/move", OperationID: "moveMachineGroup",
			Summary:     "Move a machine group under a new parent",
			Description: "Reparents the group (with its whole subtree) under parent_id, or makes it a top-level group when parent_id is null; parent_id must be present in the body. Access inherits downward, so a move changes who can reach every machine in the subtree. 409 for a move that would create a cycle, nest deeper than 4 levels, name a parent that does not exist in this tenant, leave a group in the subtree with contradictory recording policies, or race a concurrent change to the group tree. Requires manage_groups.",
			Capability:  CapManageGroups, ResponseKey: "machine_group",
			RequestSchema: schemaObj(map[string]any{
				"parent_id": schemaNullableStr("The new parent group id, or null to make the group top-level. Required (an absent key is a 400)."),
			}, "parent_id"),
			SuccessSchema:  schemaEnvelope("machine_group", schemaObj(map[string]any{"id": schemaStr(""), "name": schemaStr(""), "parent_id": schemaNullableStr("")})),
			ExtraResponses: map[int]string{http.StatusConflict: "The move would create a cycle, exceed the 4-level depth cap, name an unknown parent, conflict with a recording policy, or raced a change to the tree; nothing moved."},
			handler:        func(s *Server) http.HandlerFunc { return s.handleMoveMachineGroup },
		},
		{
			Method: "DELETE", Path: "/machine-groups/{id}", OperationID: "deleteMachineGroup",
			Summary:     "Delete a machine group",
			Description: "Deletes an EMPTY machine group. A group that still has machines or subgroups (or is referenced by enrollment tokens) answers 409 and nothing changes; move or remove them first. Requires manage_groups.",
			Capability:  CapManageGroups, ResponseKey: "deleted",
			SuccessSchema:  schemaObj(map[string]any{"deleted": map[string]any{"type": "boolean"}, "id": schemaStr("")}, "deleted", "id"),
			ExtraResponses: map[int]string{http.StatusConflict: "The group is still in use (machines, subgroups or enrollment tokens reference it); nothing was deleted."},
			handler:        func(s *Server) http.HandlerFunc { return s.handleDeleteMachineGroup },
		},
		{
			Method: "POST", Path: "/machines/{id}/group", OperationID: "setMachineGroup",
			Summary:     "Move a machine to a group",
			Description: "Moves the machine into the body's group_id. Requires manage_machines covering BOTH the machine's current group and the target group (an API token's grant is tenant-wide, so both hold whenever the capability is granted). Returns the updated machine.",
			Capability:  CapManageMachines, ResponseKey: "machine",
			RequestSchema: schemaObj(map[string]any{"group_id": schemaStr("The target machine group id, as returned by listMachineGroups.")}, "group_id"),
			SuccessSchema: schemaEnvelope("machine", map[string]any{"type": "object"}),
			handler:       func(s *Server) http.HandlerFunc { return s.handleSetMachineGroup },
		},
		{
			Method: "POST", Path: "/machines/bulk-group", OperationID: "bulkSetMachineGroup",
			Summary:     "Move many machines to one group",
			Description: "Moves up to 200 machines into one target group. PARTIAL SUCCESS IS NORMAL and still answers HTTP 200: inspect each results[] item - ok:false with an error means that machine was not moved (except the error 'could not record audit', where the move committed without its audit row). A duplicate machine id is processed twice; the second pass is a no-op move. Requires manage_machines; an inaccessible or unknown TARGET group fails the whole request.",
			Capability:  CapManageMachines, ResponseKey: "results", OwnAuditCaveat: true,
			RequestSchema: schemaObj(map[string]any{
				"machine_ids": schemaArr(schemaStr("Machine primary keys, at most 200.")),
				"group_id":    schemaStr("The target machine group id."),
			}, "machine_ids", "group_id"),
			SuccessSchema: schemaEnvelope("results", schemaArr(schemaObj(map[string]any{
				"machine_id": schemaStr(""),
				"ok":         map[string]any{"type": "boolean"},
				"error":      schemaStr("Set when ok is false."),
			}, "machine_id", "ok"))),
			handler: func(s *Server) http.HandlerFunc { return s.handleBulkSetMachineGroup },
		},
		{
			Method: "PUT", Path: "/machines/{id}/properties/{key}", OperationID: "setMachineProperty",
			Summary:     "Set a machine property",
			Description: "Idempotent upsert of one custom property on the machine; the key is the path segment (at most 128 bytes), the value travels in the body (at most 4096 bytes). Requires manage_machines for the machine's group.",
			Capability:  CapManageMachines, ResponseKey: "property",
			RequestSchema: schemaObj(map[string]any{"value": schemaStr("The property value, at most 4096 bytes.")}, "value"),
			SuccessSchema: schemaEnvelope("property", schemaObj(map[string]any{"key": schemaStr(""), "value": schemaStr("")}, "key", "value")),
			handler:       func(s *Server) http.HandlerFunc { return s.handleSetMachineProperty },
		},
		{
			Method: "DELETE", Path: "/machines/{id}/properties/{key}", OperationID: "deleteMachineProperty",
			Summary:     "Delete a machine property",
			Description: "Removes one custom property. Deleting an absent key answers 404. Requires manage_machines for the machine's group.",
			Capability:  CapManageMachines, ResponseKey: "deleted",
			SuccessSchema: schemaObj(map[string]any{"deleted": map[string]any{"type": "boolean"}, "key": schemaStr("")}, "deleted", "key"),
			handler:       func(s *Server) http.HandlerFunc { return s.handleDeleteMachineProperty },
		},
	}
}

// registerPublicAPI mounts the versioned routes on the protected chain and the (public) spec
// discovery route on the root mux. Called from Handler() just before the "/" catch-all.
func (s *Server) registerPublicAPI(protected, root *http.ServeMux) {
	for _, rt := range publicAPIRoutes() {
		protected.HandleFunc(rt.Method+" "+publicAPIBasePath+rt.Path, rt.handler(s))
	}
	// Spec discovery is PUBLIC: the document describes shapes and the capability each route requires
	// — it carries no tenant data — so, like /auth/login, it sits outside the auth chain. Served at a
	// stable well-known path and beside the versioned surface.
	//
	// The server url is RELATIVE to each document's own location (OpenAPI 3.1 resolves a relative
	// server url against the document's URL). The control plane does not know its public prefix:
	// the reverse proxy strips /cp, so an absolute "/api/v1" sent clients to the site root, where
	// nothing answers. Relative, both locations resolve to the versioned surface under any prefix.
	root.HandleFunc("GET /api/openapi.json", handlePublicAPISpec("./"+PublicAPIVersion))
	root.HandleFunc("GET "+publicAPIBasePath+"/openapi.json", handlePublicAPISpec("../"+PublicAPIVersion))
}

// handlePublicAPISpec serves the generated OpenAPI 3.1 document, advertising serverURL.
func handlePublicAPISpec(serverURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// The spec is derived from compiled-in route metadata; it changes only with a new build.
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(buildOpenAPIDocument(serverURL))
	}
}

// buildOpenAPIDocument renders publicAPIRoutes() as an OpenAPI 3.1 document. Path keys are relative
// to the single server url, which is the standard OpenAPI composition.
func buildOpenAPIDocument(serverURL string) map[string]any {
	paths := map[string]any{}
	for _, rt := range publicAPIRoutes() {
		successStatus := rt.SuccessStatus
		if successStatus == 0 {
			successStatus = http.StatusOK
		}
		successSchema := rt.SuccessSchema
		if successSchema == nil {
			successSchema = map[string]any{"type": "object"}
		}
		responses := map[string]any{
			strconv.Itoa(successStatus): map[string]any{
				"description": "Success. The payload is under the \"" + rt.ResponseKey + "\" key.",
				"content": map[string]any{
					"application/json": map[string]any{
						"schema": successSchema,
					},
				},
			},
			"401": map[string]any{"description": "No valid credential (missing or expired token)."},
			"403": map[string]any{"description": "The token lacks the required capability (" + string(rt.Capability) + ") for this tenant or group."},
		}
		for status, desc := range rt.ExtraResponses {
			responses[strconv.Itoa(status)] = map[string]any{"description": desc}
		}
		description := rt.Description
		if rt.Method != http.MethodGet && !rt.OwnAuditCaveat {
			// One generated sentence per write, so the retry contract cannot drift per row: the aliased
			// handlers audit AFTER mutating and fail the request if the audit cannot be recorded. A row
			// whose handler has DIFFERENT audit-failure semantics documents them itself (OwnAuditCaveat).
			description += " If recording the audit event fails after the mutation committed, the response" +
				" is a 500 even though the change persisted - check state before retrying a non-idempotent call."
		}
		op := map[string]any{
			"operationId":           rt.OperationID,
			"summary":               rt.Summary,
			"description":           description,
			"x-required-capability": string(rt.Capability),
			"security":              []any{map[string]any{"bearerAuth": []any{}}},
			"responses":             responses,
		}
		if rt.RequestSchema != nil {
			responses["400"] = map[string]any{"description": "Malformed or invalid request body."}
			op["requestBody"] = map[string]any{
				"required": true,
				"content": map[string]any{
					"application/json": map[string]any{"schema": rt.RequestSchema},
				},
			}
		}
		// Document EVERY {name} placeholder in the path (a {key} segment undeclared in the spec would
		// make the document invalid), not a single hard-coded "id".
		if names := pathParamNames(rt.Path); len(names) > 0 {
			params := make([]any, 0, len(names))
			for _, name := range names {
				desc := "Path identifier segment."
				switch name {
				case "id":
					desc = "Primary key of the resource, as returned by the corresponding list operation."
				case "key":
					desc = "The property key: one path segment of at most 128 bytes."
				}
				params = append(params, map[string]any{
					"name":        name,
					"in":          "path",
					"required":    true,
					"schema":      map[string]any{"type": "string"},
					"description": desc,
				})
			}
			op["parameters"] = params
			responses["404"] = map[string]any{"description": "No such resource in this tenant."}
		}
		entry, ok := paths[rt.Path].(map[string]any)
		if !ok {
			entry = map[string]any{}
			paths[rt.Path] = entry
		}
		entry[strings.ToLower(rt.Method)] = op
	}
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "DeskRally Public API",
			"version": "1.0.0",
			"description": "Fleet, session, and audit queries plus fleet write operations (machine groups, " +
				"machine moves, machine properties) for automation. Authenticate with a tenant-admin-minted " +
				"API token (Authorization: Bearer <token>). A token is its own principal, carries a bounded " +
				"capability subset that applies TENANT-WIDE, and is confined to its tenant by row-level " +
				"security; its writes are recorded in the management audit trail with the token as the actor. " +
				"Interactive-session creation and user management are intentionally not exposed to tokens — " +
				"they require a real accountable human.",
		},
		"servers": []any{map[string]any{"url": serverURL}},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":        "http",
					"scheme":      "bearer",
					"description": "A DeskRally API token. Mint one with POST /api-tokens (console: API Tokens).",
				},
			},
		},
		"security": []any{map[string]any{"bearerAuth": []any{}}},
		"paths":    paths,
	}
}

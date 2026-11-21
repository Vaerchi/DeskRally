package controlplane

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
)

func decodeLanRequest(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInternalDirectiveBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err == nil {
		if err := dec.Decode(new(json.RawMessage)); err == io.EOF {
			return true
		}
	}
	writeError(w, http.StatusBadRequest, string(LanBadRequest))
	return false
}

func (s *Server) handleGetSignalingIncarnation(w http.ResponseWriter, r *http.Request) {
	if !s.internalDirectiveAuth(w, r) {
		return
	}
	id, revision, err := s.LAN.GetSignalingIncarnation(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "revision": revision})
}

func (s *Server) handleActivateSignalingIncarnation(w http.ResponseWriter, r *http.Request) {
	if !s.internalDirectiveAuth(w, r) {
		return
	}
	var body struct {
		Incarnation      string `json:"incarnation"`
		ExpectedRevision *int64 `json:"expected_revision"`
	}
	if !decodeLanRequest(w, r, &body) {
		return
	}
	if _, valid := parsePgUUID(body.Incarnation); !valid || body.ExpectedRevision == nil || *body.ExpectedRevision < 0 {
		writeError(w, http.StatusBadRequest, string(LanBadRequest))
		return
	}
	ok, revision, err := s.LAN.ActivateSignalingIncarnation(r.Context(), body.Incarnation, *body.ExpectedRevision)
	switch {
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal_error")
	case !ok:
		writeJSON(w, http.StatusConflict, map[string]any{"error": "revision_moved", "revision": revision})
	default:
		writeJSON(w, http.StatusOK, map[string]int64{"revision": revision})
	}
}

type lanConnectionBody struct {
	DeviceID     string `json:"device_id"`
	DevicePubKey string `json:"device_pubkey"`
	Incarnation  string `json:"incarnation"`
	Generation   *int64 `json:"generation"`
}

func (s *Server) handleAllocateLanEpoch(w http.ResponseWriter, r *http.Request) {
	if !s.internalDirectiveAuth(w, r) {
		return
	}
	var body lanConnectionBody
	if !decodeLanRequest(w, r, &body) {
		return
	}
	if body.Generation == nil {
		writeError(w, http.StatusBadRequest, string(LanBadRequest))
		return
	}
	epoch, outcome, err := s.LAN.AllocateLanEpoch(r.Context(), body.DeviceID, body.DevicePubKey, body.Incarnation, *body.Generation)
	if err != nil || outcome != "" {
		writeLanOutcome(w, outcome, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"epoch": epoch})
}

func (s *Server) handleIngestLanReport(w http.ResponseWriter, r *http.Request) {
	if !s.internalDirectiveAuth(w, r) {
		return
	}
	var body struct {
		lanConnectionBody
		Epoch   *int64     `json:"epoch"`
		Seq     *int64     `json:"seq"`
		Digest  string     `json:"digest"`
		Entries []LanEntry `json:"entries"`
	}
	if !decodeLanRequest(w, r, &body) {
		return
	}
	digest, err := hex.DecodeString(body.Digest)
	if err != nil || body.Generation == nil || body.Epoch == nil || body.Seq == nil || body.Entries == nil {
		writeError(w, http.StatusBadRequest, string(LanBadRequest))
		return
	}
	outcome, err := s.LAN.IngestLanReport(r.Context(), body.DeviceID, body.DevicePubKey, body.Incarnation,
		*body.Generation, *body.Epoch, *body.Seq, digest, body.Entries)
	writeLanOutcome(w, outcome, err)
}

func writeLanOutcome(w http.ResponseWriter, outcome LanOutcome, err error) {
	switch {
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal_error")
	case outcome == LanBadRequest:
		writeError(w, http.StatusBadRequest, string(outcome))
	case outcome == LanApplied || outcome == LanDuplicate || outcome == LanDropped:
		writeJSON(w, http.StatusOK, map[string]LanOutcome{"status": outcome})
	default:
		writeError(w, http.StatusConflict, string(outcome))
	}
}

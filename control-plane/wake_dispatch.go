package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WakeConnRef struct {
	Incarnation string `json:"incarnation"`
	Generation  int64  `json:"generation"`
}

type WakeContext struct {
	ConnRef         WakeConnRef
	Epoch           int64
	Challenge       [16]byte
	DeviceKeySHA256 [32]byte
}

type WakeOutcome string

const (
	WakeContextReady WakeOutcome = "ready"
	WakeNotReady     WakeOutcome = "not_ready"
	WakeNotWritten   WakeOutcome = "not_written"
	WakeWritten      WakeOutcome = "written"
	WakeWriteFailed  WakeOutcome = "write_failed"
	WakeNoAnswer     WakeOutcome = "no_answer"
)

type WakeDispatcher interface {
	WakeContext(ctx context.Context, relayDeviceID string) (WakeContext, WakeOutcome)
	Forward(ctx context.Context, relayDeviceID string, connRef WakeConnRef, artifact []byte) WakeOutcome
}

// HTTPWakeDispatcher sends authenticated POSTs under /internal/devices/{id}.
// /wake-context takes an empty body and returns HTTP 200 with
// {conn_ref:{incarnation:<UUID>,generation:<integer>},epoch:<integer>,
// challenge:<32 lowercase hex characters>,device_key_sha256:<64 lowercase hex characters>}.
// HTTP 409 with error "not_ready" is a confirmed context refusal.
// /wake takes {conn_ref:<same object>,artifact:{claims:<RMTWAKEv1 claims>,sig:<hex>}}.
// HTTP 202 means written. HTTP 409 and 502 require the corresponding JSON error code.
// Transport errors, malformed context replies and other statuses are ambiguous.
type HTTPWakeDispatcher struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

var _ WakeDispatcher = (*HTTPWakeDispatcher)(nil)

func (d *HTTPWakeDispatcher) post(ctx context.Context, deviceID, endpoint string, body []byte) *http.Response {
	if d.BaseURL == "" || d.Token == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(d.BaseURL, "/")+"/internal/devices/"+url.PathEscape(deviceID)+endpoint,
		bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+d.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := http.Client{Timeout: 8 * time.Second}
	if d.Client != nil {
		client = *d.Client
	}
	// Avoid replaying a request or following a redirect to a different service.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	return resp
}

func (d *HTTPWakeDispatcher) WakeContext(ctx context.Context, id string) (WakeContext, WakeOutcome) {
	resp := d.post(ctx, id, "/wake-context", nil)
	if resp == nil {
		return WakeContext{}, WakeNoAnswer
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict && wakeResponseError(resp) == "not_ready" {
		return WakeContext{}, WakeNotReady
	}
	var wire struct {
		ConnRef struct {
			Incarnation string `json:"incarnation"`
			Generation  *int64 `json:"generation"`
		} `json:"conn_ref"`
		Epoch           *int64 `json:"epoch"`
		Challenge       string `json:"challenge"`
		DeviceKeySHA256 string `json:"device_key_sha256"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK || dec.Decode(&wire) != nil || dec.Decode(new(json.RawMessage)) != io.EOF {
		return WakeContext{}, WakeNoAnswer
	}
	incarnation, valid := parsePgUUID(wire.ConnRef.Incarnation)
	challenge, challengeErr := wakeHex(wire.Challenge, 16)
	hash, hashErr := wakeHex(wire.DeviceKeySHA256, 32)
	if !valid || wire.ConnRef.Generation == nil || *wire.ConnRef.Generation < 0 ||
		wire.Epoch == nil || *wire.Epoch < 0 || challengeErr != nil || hashErr != nil {
		return WakeContext{}, WakeNoAnswer
	}
	result := WakeContext{ConnRef: WakeConnRef{Incarnation: incarnation, Generation: *wire.ConnRef.Generation}, Epoch: *wire.Epoch}
	copy(result.Challenge[:], challenge)
	copy(result.DeviceKeySHA256[:], hash)
	return result, WakeContextReady
}

func wakeResponseError(resp *http.Response) string {
	const maxErrorBody = 4096
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody+1))
	if err != nil || len(body) > maxErrorBody {
		return ""
	}
	// Require exactly one error field so duplicate keys cannot confirm a refusal.
	dec := json.NewDecoder(bytes.NewReader(body))
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return ""
	}
	if token, err := dec.Token(); err != nil || token != "error" {
		return ""
	}
	var code string
	if dec.Decode(&code) != nil {
		return ""
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') {
		return ""
	}
	if _, err := dec.Token(); err != io.EOF {
		return ""
	}
	return code
}

func (d *HTTPWakeDispatcher) Forward(ctx context.Context, id string, ref WakeConnRef, artifact []byte) WakeOutcome {
	body, err := json.Marshal(struct {
		ConnRef  WakeConnRef     `json:"conn_ref"`
		Artifact json.RawMessage `json:"artifact"`
	}{ref, artifact})
	if err != nil {
		return WakeNoAnswer
	}
	resp := d.post(ctx, id, "/wake", body)
	if resp == nil {
		return WakeNoAnswer
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusAccepted:
		return WakeWritten
	case http.StatusConflict:
		if wakeResponseError(resp) == "not_written" {
			return WakeNotWritten
		}
	case http.StatusBadGateway:
		if wakeResponseError(resp) == "write_failed" {
			return WakeWriteFailed
		}
	}
	return WakeNoAnswer
}

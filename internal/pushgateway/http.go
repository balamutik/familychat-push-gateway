package pushgateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/balamutik/familychat-push-gateway/internal/pushprotocol"
)

type Sender interface {
	Send(context.Context, string, string, json.RawMessage) (bool, error)
}
type rateWindow struct {
	start time.Time
	count int
}
type Handler struct {
	store     *Store
	sender    Sender
	apns, fcm bool
	mu        sync.Mutex
	windows   map[string]rateWindow
	active    map[string]int
	perMinute int
	slots     chan struct{}
}

func NewHandler(store *Store, sender Sender, apns, fcm bool) *Handler {
	return &Handler{store: store, sender: sender, apns: apns, fcm: fcm, windows: map[string]rateWindow{}, active: map[string]int{}, perMinute: 240, slots: make(chan struct{}, 32)}
}
func (h *Handler) enter(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active[id] >= 4 {
		return false
	}
	h.active[id]++
	return true
}
func (h *Handler) leave(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.active[id]--
	if h.active[id] == 0 {
		delete(h.active, id)
	}
}
func (h *Handler) allow(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	for key, v := range h.windows {
		if now.Sub(v.start) >= time.Minute {
			delete(h.windows, key)
		}
	}
	w := h.windows[id]
	if w.start.IsZero() {
		w.start = now
	}
	w.count++
	h.windows[id] = w
	return w.count <= h.perMinute
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}
func fail(w http.ResponseWriter, status int, code string) {
	reply(w, status, map[string]string{"error": code})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		fail(w, 415, "json_required")
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, pushprotocol.MaxBodyBytes))
	if err != nil {
		fail(w, 413, "body_too_large")
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil {
		fail(w, 400, "invalid_request")
		return false
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		fail(w, 400, "invalid_request")
		return false
	}
	return true
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path == "/health/live" && r.Method == "GET" {
		reply(w, 200, map[string]string{"status": "ok"})
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		fail(w, 503, "busy")
		return
	}
	credential, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !pushprotocol.ValidCredential(credential) {
		fail(w, 401, "unauthorized")
		return
	}
	id, err := h.store.Authenticate(credential)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			fail(w, 401, "unauthorized")
		} else {
			fail(w, 503, "state_unavailable")
		}
		return
	}
	if !h.allow(id) {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "rate_limited")
		return
	}
	if !h.enter(id) {
		w.Header().Set("Retry-After", "1")
		fail(w, 429, "client_busy")
		return
	}
	defer h.leave(id)
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/status":
		reply(w, 200, map[string]any{"protocol": 1, "apns": h.apns, "fcm": h.fcm})
	case r.Method == "POST" && r.URL.Path == "/v1/devices":
		var body pushprotocol.Registration
		if !decode(w, r, &body) {
			return
		}
		if !pushprotocol.ValidDevice(body.Kind, body.Token) {
			fail(w, 400, "invalid_device")
			return
		}
		if !h.enabled(body.Kind) {
			fail(w, 503, "provider_unavailable")
			return
		}
		if body.Kind != "fcm" {
			body.Token = strings.ToLower(body.Token)
		}
		device, err := h.store.Register(id, body.Kind, body.Token)
		if err != nil {
			storeError(w, err)
			return
		}
		reply(w, 201, pushprotocol.RegistrationResult{ID: device})
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/devices/"):
		if err := h.store.DeleteDevice(id, strings.TrimPrefix(r.URL.Path, "/v1/devices/")); err != nil {
			storeError(w, err)
			return
		}
		reply(w, 204, nil)
	case r.Method == "POST" && r.URL.Path == "/v1/push":
		var body pushprotocol.Request
		if !decode(w, r, &body) {
			return
		}
		payload, err := body.Event.Payload(body.Kind, time.Now())
		if err != nil {
			fail(w, 400, "invalid_event")
			return
		}
		device, err := h.store.Device(id, body.DeviceID)
		if err != nil {
			storeError(w, err)
			return
		}
		if device.Kind != pushprotocol.DeviceKind(body.Kind) {
			fail(w, 400, "device_kind_mismatch")
			return
		}
		if !h.enabled(device.Kind) {
			fail(w, 503, "provider_unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		invalid, err := h.sender.Send(ctx, device.Token, body.Kind, payload)
		if invalid {
			if e := h.store.DeleteDevice(id, device.ID); e != nil {
				storeError(w, e)
				return
			}
			fail(w, 410, "device_unregistered")
			return
		}
		if err != nil {
			fail(w, 502, "delivery_failed")
			return
		}
		reply(w, 204, nil)
	default:
		fail(w, 404, "not_found")
	}
}
func (h *Handler) enabled(kind string) bool {
	if kind == "fcm" {
		return h.fcm
	}
	return h.apns
}
func storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnauthorized):
		fail(w, 401, "unauthorized")
	case errors.Is(err, ErrNotFound):
		fail(w, 404, "not_found")
	case errors.Is(err, ErrQuota):
		fail(w, 429, "device_quota")
	default:
		fail(w, 503, "state_unavailable")
	}
}

package pushgateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type captureSender struct {
	count       int
	token, kind string
	payload     json.RawMessage
	invalid     bool
	err         error
}

func (s *captureSender) Send(_ context.Context, token, kind string, payload json.RawMessage) (bool, error) {
	s.count++
	s.token = token
	s.kind = kind
	s.payload = payload
	return s.invalid, s.err
}
func setup(t *testing.T) (*Store, *Handler, *captureSender, string, string) {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "gateway", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.AddClient("family-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.AddClient("family-b")
	if err != nil {
		t.Fatal(err)
	}
	sender := &captureSender{}
	return store, NewHandler(store, sender, true, true), sender, a, b
}
func request(h http.Handler, token, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func register(t *testing.T, h http.Handler, token, kind string) string {
	t.Helper()
	deviceToken := strings.Repeat("a", 64)
	if kind == "fcm" {
		deviceToken = "opaque:FCM-device"
	}
	w := request(h, token, "POST", "/v1/devices", `{"kind":"`+kind+`","token":"`+deviceToken+`"}`)
	if w.Code != 201 {
		t.Fatalf("register status=%d body=%s", w.Code, w.Body.String())
	}
	var v struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v.ID
}

const event = `{"server_id":"10000000-0000-0000-0000-000000000001","chat_id":"10000000-0000-0000-0000-000000000002","message_id":"10000000-0000-0000-0000-000000000003"}`

func sendBody(id string) string {
	return `{"device_id":"` + id + `","kind":"alert","event":` + event + `}`
}
func TestTenantIsolationRevocationAndPersistence(t *testing.T) {
	store, h, s, a, b := setup(t)
	id := register(t, h, a, "alert")
	if got := register(t, h, a, "alert"); got != id {
		t.Fatal("registration must be idempotent")
	}
	if w := request(h, b, "POST", "/v1/push", sendBody(id)); w.Code != 404 {
		t.Fatalf("cross tenant status %d", w.Code)
	}
	if s.count != 0 {
		t.Fatal("cross tenant delivery")
	}
	if w := request(h, a, "POST", "/v1/push", sendBody(id)); w.Code != 204 {
		t.Fatalf("send %d %s", w.Code, w.Body.String())
	}
	if s.count != 1 || s.token != strings.Repeat("a", 64) {
		t.Fatal("wrong delivery")
	}
	reopened, err := Open(store.path)
	if err != nil {
		t.Fatal(err)
	}
	h2 := NewHandler(reopened, s, true, true)
	if w := request(h2, a, "POST", "/v1/push", sendBody(id)); w.Code != 204 {
		t.Fatalf("restart %d", w.Code)
	}
	if err := reopened.RevokeClient(strings.Split(a, ".")[0]); err != nil {
		t.Fatal(err)
	}
	if w := request(h, a, "POST", "/v1/push", sendBody(id)); w.Code != 401 {
		t.Fatalf("revocation must be live: %d", w.Code)
	}
}
func TestRejectsUnsafeRequestsBeforeDelivery(t *testing.T) {
	_, h, s, a, _ := setup(t)
	id := register(t, h, a, "alert")
	for _, test := range []struct {
		token, path, body string
		status            int
	}{
		{"bad", "/v1/push", sendBody(id), 401},
		{a, "/v1/push", strings.Replace(sendBody(id), `"alert"`, `"voip"`, 1), 400},
		{a, "/v1/push", strings.Replace(sendBody(id), `"event":`, `"url":"http://169.254.169.254/","event":`, 1), 400},
		{a, "/v1/push", strings.Replace(sendBody(id), `"server_id":`, `"text":"secret","server_id":`, 1), 400},
		{a, "/v1/push", sendBody(id) + `{}`, 400},
		{a, "/v1/devices", `{"kind":"alert","token":"../../secret"}`, 400},
		{a, "/v1/devices", strings.Repeat("x", 20000), 413},
	} {
		w := request(h, test.token, "POST", test.path, test.body)
		if w.Code != test.status {
			t.Errorf("%s status=%d want=%d", test.path, w.Code, test.status)
		}
	}
	if s.count != 0 {
		t.Fatal("invalid request reached provider")
	}
}
func TestGenericPayloadAndPermanentTokenFailure(t *testing.T) {
	_, h, s, a, _ := setup(t)
	id := register(t, h, a, "alert")
	w := request(h, a, "POST", "/v1/push", sendBody(id))
	if w.Code != 204 {
		t.Fatal(w.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(s.payload, &payload); err != nil {
		t.Fatal(err)
	}
	alert := payload["aps"].(map[string]any)["alert"].(map[string]any)
	if alert["title"] != "FamilyChat" || alert["body"] != "Новое сообщение" {
		t.Fatal(string(s.payload))
	}
	s.invalid = true
	if w = request(h, a, "POST", "/v1/push", sendBody(id)); w.Code != 410 {
		t.Fatalf("invalid token: %d", w.Code)
	}
	if w = request(h, a, "POST", "/v1/push", sendBody(id)); w.Code != 404 {
		t.Fatalf("invalid device retained: %d", w.Code)
	}
}
func TestLimitsAndDisabledProviders(t *testing.T) {
	store, h, _, a, _ := setup(t)
	h = NewHandler(store, &captureSender{}, false, true)
	if w := request(h, a, "POST", "/v1/devices", `{"kind":"alert","token":"`+strings.Repeat("a", 64)+`"}`); w.Code != 503 {
		t.Fatal(w.Code)
	}
	h = NewHandler(store, &captureSender{}, true, true)
	h.perMinute = 2
	for i := 0; i < 2; i++ {
		if w := request(h, a, "GET", "/v1/status", ""); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	if w := request(h, a, "GET", "/v1/status", ""); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("missing rate limit")
	}
}
func TestVoIPExpiryAndFCMState(t *testing.T) {
	_, h, s, a, _ := setup(t)
	id := register(t, h, a, "voip")
	ev := `{"server_id":"10000000-0000-0000-0000-000000000001","chat_id":"10000000-0000-0000-0000-000000000002","call_id":"10000000-0000-0000-0000-000000000004","kind":"audio","expires_at":`
	for _, expiry := range []int64{time.Now().Add(-time.Second).Unix(), time.Now().Add(time.Hour).Unix()} {
		body := map[string]any{"device_id": id, "kind": "voip", "event": json.RawMessage(ev + jsonNumber(expiry) + `}`)}
		raw, _ := json.Marshal(body)
		if w := request(h, a, "POST", "/v1/push", string(raw)); w.Code != 400 {
			t.Fatalf("invalid call expiry %d", w.Code)
		}
	}
	if s.count != 0 {
		t.Fatal("expired call sent")
	}
}
func jsonNumber(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestAllSupportedEventsProduceNativePayloads(t *testing.T) {
	_, h, s, a, _ := setup(t)
	for _, tc := range []struct{ device, kind, fields string }{
		{"voip", "voip", `"call_id":"10000000-0000-0000-0000-000000000004","kind":"video","expires_at":` + jsonNumber(time.Now().Add(40*time.Second).Unix())},
		{"fcm", "fcm_call", `"call_id":"10000000-0000-0000-0000-000000000004","kind":"audio","expires_at":` + jsonNumber(time.Now().Add(40*time.Second).Unix())},
		{"fcm", "fcm_message", `"message_id":"10000000-0000-0000-0000-000000000003"`},
		{"fcm", "fcm_call_state", `"call_id":"10000000-0000-0000-0000-000000000004","state":"cancelled"`},
	} {
		id := register(t, h, a, tc.device)
		body := `{"device_id":"` + id + `","kind":"` + tc.kind + `","event":{"server_id":"10000000-0000-0000-0000-000000000001","chat_id":"10000000-0000-0000-0000-000000000002",` + tc.fields + `}}`
		if w := request(h, a, "POST", "/v1/push", body); w.Code != 204 {
			t.Fatalf("%s %d %s", tc.kind, w.Code, w.Body.String())
		}
		var payload map[string]any
		json.Unmarshal(s.payload, &payload)
		if s.kind != tc.kind || payload["server_id"] != "10000000-0000-0000-0000-000000000001" {
			t.Fatal("lost routing")
		}
		if tc.kind == "voip" && payload["aps"].(map[string]any)["content-available"] != float64(1) {
			t.Fatal("missing VoIP APS")
		}
		if strings.HasPrefix(tc.kind, "fcm_") && payload["client_server_id"] != payload["server_id"] {
			t.Fatal("lost Android routing")
		}
	}
}

func TestRegistrationQuotaDoesNotAffectOtherTenant(t *testing.T) {
	store, h, _, a, b := setup(t)
	tenant := strings.Split(a, ".")[0]
	if err := store.withState(func(d *diskState) (bool, error) {
		for i := 0; i < 1000; i++ {
			id := jsonNumber(int64(i))
			d.Devices[id] = Device{ID: id, ClientID: tenant, Kind: "fcm", Token: "existing-" + id, SeenAt: time.Now().Unix()}
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if w := request(h, a, "POST", "/v1/devices", `{"kind":"fcm","token":"new-token"}`); w.Code != 429 {
		t.Fatalf("quota: %d", w.Code)
	}
	register(t, h, b, "fcm")
}

type blockedSender struct {
	entered chan struct{}
	release chan struct{}
}

func (s blockedSender) Send(ctx context.Context, _ string, _ string, _ json.RawMessage) (bool, error) {
	s.entered <- struct{}{}
	select {
	case <-s.release:
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}
func TestSlowTenantCannotOccupyOtherTenantsDeliverySlots(t *testing.T) {
	store, _, _, a, b := setup(t)
	sender := blockedSender{make(chan struct{}, 4), make(chan struct{})}
	var requests sync.WaitGroup
	defer func() {
		close(sender.release)
		requests.Wait()
	}()
	h := NewHandler(store, sender, true, true)
	id := register(t, h, a, "alert")
	for i := 0; i < 4; i++ {
		requests.Add(1)
		go func() {
			defer requests.Done()
			request(h, a, "POST", "/v1/push", sendBody(id))
		}()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-sender.entered:
		case <-time.After(time.Second):
			t.Fatal("request did not enter sender")
		}
	}
	w := request(h, a, "GET", "/v1/status", "")
	if w.Code != 429 {
		t.Fatalf("overloaded tenant not bounded: %d", w.Code)
	}
	if w = request(h, b, "GET", "/v1/status", ""); w.Code != 200 {
		t.Fatalf("other tenant starved: %d", w.Code)
	}
}

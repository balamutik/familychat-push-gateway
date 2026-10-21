package push

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFCMProviderUsesOAuthAndOnlyRoutingData(t *testing.T) {
	var authorizationCount, sendCount int
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	secret, _ := json.Marshal(map[string]string{"project_id": "test-project", "client_email": "test@example.test", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			authorizationCount++
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if len(strings.Split(r.Form.Get("assertion"), ".")) != 3 {
				t.Error("missing signed assertion")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"oauth-token","expires_in":3600}`))
		case "/v1/projects/test-project/messages:send":
			sendCount++
			if r.Header.Get("Authorization") != "Bearer oauth-token" {
				t.Error("missing OAuth")
			}
			var body struct {
				Message struct {
					Token   string            `json:"token"`
					Data    map[string]string `json:"data"`
					Android struct {
						TTL                   string `json:"ttl"`
						RestrictedPackageName string `json:"restricted_package_name"`
					} `json:"android"`
				} `json:"message"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Message.Token != "opaque:FCM-token" || body.Message.Data["server_id"] != "server" || body.Message.Data["event_type"] != "message" {
				t.Errorf("bad routing: %+v", body)
			}
			if _, ok := body.Message.Data["text"]; ok {
				t.Error("plaintext must not be sent")
			}
			if body.Message.Android.RestrictedPackageName != "com.familychat.android" {
				t.Error("missing app restriction")
			}
			_, _ = w.Write([]byte(`{"name":"projects/test/messages/1"}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, err := newFCM(secret, "test-project", "com.familychat.android", server.Client(), server.URL, server.URL+"/token")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		invalid, err := client.Send(context.Background(), "opaque:FCM-token", "fcm_message", json.RawMessage(`{"server_id":"server","chat_id":"chat","message_id":"message","text":"must not leak"}`))
		if invalid || err != nil {
			t.Fatalf("send invalid=%v err=%v", invalid, err)
		}
	}
	if authorizationCount != 1 || sendCount != 2 {
		t.Fatalf("token caching auth=%d send=%d", authorizationCount, sendCount)
	}
}
func TestFCMCallTTLAndExpiredCall(t *testing.T) {
	ttl, ok := fcmTTL("fcm_call", map[string]any{"expires_at": float64(time.Now().Add(20 * time.Second).Unix())}, time.Now())
	if !ok || ttl <= 0 || ttl > 20*time.Second {
		t.Fatalf("ttl=%v ok=%v", ttl, ok)
	}
	if _, ok := fcmTTL("fcm_call", map[string]any{"expires_at": float64(time.Now().Add(-time.Second).Unix())}, time.Now()); ok {
		t.Fatal("expired call must not send")
	}
}

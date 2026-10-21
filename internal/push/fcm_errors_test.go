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
	"testing"
)

func TestFCMUnregisteredIsOnlyPermanentTokenFailure(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	secret, _ := json.Marshal(map[string]string{"project_id": "test", "client_email": "qa@example.test", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	status := 404
	code := "UNREGISTERED"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"details": []map[string]string{{"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": code}}}})
	}))
	defer server.Close()
	client, err := newFCM(secret, "test", "com.familychat.android", server.Client(), server.URL, server.URL+"/token")
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := client.Send(context.Background(), "opaque-token", "fcm_message", json.RawMessage(`{"server_id":"id"}`))
	if !invalid || err != nil {
		t.Fatalf("unregistered invalid=%v err=%v", invalid, err)
	}
	for _, tc := range []struct {
		status int
		code   string
	}{{400, "INVALID_ARGUMENT"}, {403, "SENDER_ID_MISMATCH"}, {500, "INTERNAL"}} {
		status, code = tc.status, tc.code
		invalid, err = client.Send(context.Background(), "opaque-token", "fcm_message", json.RawMessage(`{"server_id":"id"}`))
		if invalid || err == nil {
			t.Errorf("HTTP %d %s must retain token", status, code)
		}
	}
}

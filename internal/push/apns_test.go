package push

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSendUsesVoIPTopicAndHeaders(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = true
		if r.URL.Path != "/3/device/abc" || r.Header.Get("apns-topic") != "com.example.chat.voip" ||
			r.Header.Get("apns-push-type") != "voip" || r.Header.Get("apns-expiration") != "0" ||
			!strings.HasPrefix(r.Header.Get("authorization"), "bearer ") {
			t.Errorf("unexpected APNs request: path=%s headers=%v", r.URL.Path, r.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	client := &Client{key: key, keyID: "K", teamID: "T", topic: "com.example.chat", endpoint: "https://test.invalid", httpClient: &http.Client{Timeout: time.Second, Transport: transport}}
	invalid, err := client.Send(context.Background(), "abc", "voip", json.RawMessage(`{"aps":{"content-available":1}}`))
	if err != nil || invalid || !seen {
		t.Fatalf("Send = %v, %v, seen=%v", invalid, err, seen)
	}
}

func TestSendMarksUnregisteredTokenInvalid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusGone, Body: io.NopCloser(strings.NewReader(`{"reason":"Unregistered"}`))}, nil
	})
	client := &Client{key: key, keyID: "K", teamID: "T", topic: "com.example.chat", endpoint: "https://test.invalid", httpClient: &http.Client{Timeout: time.Second, Transport: transport}}
	invalid, err := client.Send(context.Background(), "abc", "alert", json.RawMessage(`{"aps":{"alert":"hi"}}`))
	if !invalid || err == nil {
		t.Fatalf("Send = %v, %v", invalid, err)
	}
}

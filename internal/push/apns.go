package push

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/balamutik/familychat-push-gateway/internal/config"
)

type Client struct {
	key                            *ecdsa.PrivateKey
	keyID, teamID, topic, endpoint string
	httpClient                     *http.Client
	mu                             sync.Mutex
	jwt                            string
	jwtAt                          time.Time
}

func New(c config.Config) (*Client, error) {
	if c.APNsKeyFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(c.APNsKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read APNs key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid APNs PEM key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse APNs key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve.Params().Name != "P-256" {
		return nil, errors.New("APNs key must be P-256")
	}
	endpoint := "https://api.push.apple.com"
	if c.APNsSandbox {
		endpoint = "https://api.sandbox.push.apple.com"
	}
	return &Client{key: key, keyID: c.APNsKeyID, teamID: c.APNsTeamID, topic: c.APNsTopic,
		endpoint: endpoint, httpClient: &http.Client{Timeout: 10 * time.Second}}, nil
}

func (c *Client) authorization() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jwt != "" && time.Since(c.jwtAt) < 50*time.Minute {
		return c.jwt, nil
	}
	now := time.Now()
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": c.keyID})
	payload, _ := json.Marshal(map[string]any{"iss": c.teamID, "iat": now.Unix()})
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, digest[:])
	if err != nil {
		return "", err
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	c.jwt = signing + "." + enc.EncodeToString(signature)
	c.jwtAt = now
	return c.jwt, nil
}

// Send returns invalidToken only when APNs says this address must not be retried.
func (c *Client) Send(ctx context.Context, token, kind string, payload json.RawMessage) (invalidToken bool, err error) {
	if c == nil {
		return false, errors.New("APNs is not configured")
	}
	if kind != "alert" && kind != "voip" {
		return false, errors.New("invalid push kind")
	}
	jwt, err := c.authorization()
	if err != nil {
		return false, err
	}
	request, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/3/device/"+token, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	topic := c.topic
	if kind == "voip" {
		topic += ".voip"
	}
	request.Header.Set("authorization", "bearer "+jwt)
	request.Header.Set("apns-topic", topic)
	request.Header.Set("apns-push-type", kind)
	request.Header.Set("apns-priority", "10")
	request.Header.Set("content-type", "application/json")
	if kind == "voip" {
		request.Header.Set("apns-expiration", "0")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK {
		return false, nil
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
	var detail struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &detail)
	if response.StatusCode == http.StatusGone || strings.EqualFold(detail.Reason, "BadDeviceToken") || strings.EqualFold(detail.Reason, "DeviceTokenNotForTopic") || strings.EqualFold(detail.Reason, "Unregistered") {
		return true, fmt.Errorf("APNs rejected device token: %s", detail.Reason)
	}
	return false, fmt.Errorf("APNs status %d: %s", response.StatusCode, detail.Reason)
}

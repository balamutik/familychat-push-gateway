package push

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/balamutik/familychat-push-gateway/internal/config"
)

type FCM struct {
	key                                             *rsa.PrivateKey
	email, project, application, endpoint, tokenURI string
	http                                            *http.Client
	mu                                              sync.Mutex
	token                                           string
	expires                                         time.Time
}

func NewFCM(c config.Config) (*FCM, error) {
	if c.FCMCredentialsFile == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(c.FCMCredentialsFile)
	if err != nil {
		return nil, errors.New("cannot read FCM credentials file")
	}
	return newFCM(raw, c.FCMProjectID, c.FCMApplicationID, &http.Client{Timeout: 10 * time.Second}, "https://fcm.googleapis.com", "https://oauth2.googleapis.com/token")
}
func newFCM(raw []byte, project, application string, client *http.Client, endpoint, tokenURI string) (*FCM, error) {
	var secret struct {
		Project string `json:"project_id"`
		Email   string `json:"client_email"`
		Key     string `json:"private_key"`
	}
	if json.Unmarshal(raw, &secret) != nil || secret.Project != project || secret.Email == "" || project == "" || application == "" {
		return nil, errors.New("invalid FCM project/application credentials")
	}
	block, _ := pem.Decode([]byte(secret.Key))
	if block == nil {
		return nil, errors.New("invalid FCM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid FCM private key")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < 2048 {
		return nil, errors.New("FCM private key must be RSA 2048 or stronger")
	}
	return &FCM{key: key, email: secret.Email, project: project, application: application, http: client, endpoint: endpoint, tokenURI: tokenURI}, nil
}
func (c *FCM) authorization(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expires) > time.Minute {
		return c.token, nil
	}
	now := time.Now()
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"iss": c.email, "scope": "https://www.googleapis.com/auth/firebase.messaging", "aud": c.tokenURI, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	signed := header + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", errors.New("FCM OAuth signing failed")
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {signed + "." + enc.EncodeToString(signature)}}
	request, err := http.NewRequestWithContext(ctx, "POST", c.tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("FCM OAuth request failed")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.http.Do(request)
	if err != nil {
		return "", errors.New("FCM OAuth transport failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", fmt.Errorf("FCM OAuth HTTP %d", response.StatusCode)
	}
	var result struct {
		Token   string `json:"access_token"`
		Expires int64  `json:"expires_in"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result) != nil || result.Token == "" || result.Expires <= 0 {
		return "", errors.New("invalid FCM OAuth response")
	}
	c.token = result.Token
	c.expires = now.Add(time.Duration(min(result.Expires, 3600)) * time.Second)
	return c.token, nil
}
func fcmTTL(kind string, payload map[string]any, now time.Time) (time.Duration, bool) {
	switch kind {
	case "fcm_message":
		return 24 * time.Hour, true
	case "fcm_call_state":
		return 30 * time.Second, true
	case "fcm_call":
		raw, ok := payload["expires_at"].(float64)
		if !ok {
			return 0, false
		}
		ttl := time.Unix(int64(raw), 0).Sub(now)
		if ttl <= 0 {
			return 0, false
		}
		return min(ttl, 45*time.Second), true
	default:
		return 0, false
	}
}
func (c *FCM) Send(ctx context.Context, token, kind string, payload json.RawMessage) (bool, error) {
	if c == nil {
		return false, errors.New("FCM is not configured")
	}
	var input map[string]any
	if json.Unmarshal(payload, &input) != nil {
		return false, errors.New("invalid FCM payload")
	}
	ttl, live := fcmTTL(kind, input, time.Now())
	if !live {
		return false, nil
	}
	data := map[string]string{"event_type": strings.TrimPrefix(kind, "fcm_")}
	for _, key := range []string{"server_id", "client_server_id", "chat_id", "message_id", "call_id", "sender_name", "caller_name", "kind", "state"} {
		if value, ok := input[key].(string); ok {
			data[key] = value
		}
	}
	if expiry, ok := input["expires_at"].(float64); ok {
		data["expires_at"] = strconv.FormatInt(int64(expiry), 10)
	}
	body, _ := json.Marshal(map[string]any{"message": map[string]any{"token": token, "data": data, "android": map[string]any{"priority": "HIGH", "ttl": fmt.Sprintf("%ds", max(1, int(ttl.Seconds()))), "restricted_package_name": c.application}}})
	access, err := c.authorization(ctx)
	if err != nil {
		return false, err
	}
	request, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/v1/projects/"+url.PathEscape(c.project)+"/messages:send", bytes.NewReader(body))
	if err != nil {
		return false, errors.New("invalid FCM request")
	}
	request.Header.Set("Authorization", "Bearer "+access)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return false, errors.New("FCM transport failed")
	}
	defer response.Body.Close()
	if response.StatusCode == 200 {
		return false, nil
	}
	var failure struct {
		Error struct {
			Details []struct {
				Type string `json:"@type"`
				Code string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&failure)
	for _, detail := range failure.Error.Details {
		if detail.Type == "type.googleapis.com/google.firebase.fcm.v1.FcmError" && detail.Code == "UNREGISTERED" {
			return true, nil
		}
	}
	if response.StatusCode == 401 {
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
	}
	return false, fmt.Errorf("FCM delivery HTTP %d", response.StatusCode)
}

type Router struct {
	APNs *Client
	FCM  *FCM
}

func NewRouter(c config.Config) (*Router, error) {
	if err := c.ValidatePush(); err != nil {
		return nil, err
	}
	apns, err := New(c)
	if err != nil {
		return nil, err
	}
	fcm, err := NewFCM(c)
	if err != nil {
		return nil, err
	}
	if apns == nil && fcm == nil {
		return nil, nil
	}
	return &Router{APNs: apns, FCM: fcm}, nil
}
func (r *Router) Send(ctx context.Context, token, kind string, payload json.RawMessage) (bool, error) {
	if r == nil {
		return false, errors.New("push is not configured")
	}
	if strings.HasPrefix(kind, "fcm_") {
		return r.FCM.Send(ctx, token, kind, payload)
	}
	return r.APNs.Send(ctx, token, kind, payload)
}

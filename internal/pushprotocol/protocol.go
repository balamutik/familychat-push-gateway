// Package pushprotocol defines the deliberately narrow gateway wire protocol.
package pushprotocol

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxBodyBytes = 16 << 10

var uuid = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
var apnsToken = regexp.MustCompile(`^[a-fA-F0-9]{64,256}$`)
var fcmToken = regexp.MustCompile(`^[A-Za-z0-9_:.-]+$`)
var hostname = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || strings.ContainsAny(raw, "\r\n\t $#\\") {
		return errors.New("push gateway requires an HTTPS origin without credentials, path, query or fragment")
	}
	if !hostname.MatchString(u.Hostname()) {
		return errors.New("push gateway requires a DNS hostname or IPv4 address")
	}
	if strings.HasSuffix(u.Host, ":") {
		return errors.New("invalid push gateway port")
	}
	if u.Port() != "" {
		port, e := strconv.Atoi(u.Port())
		if e != nil || port < 1 || port > 65535 {
			return errors.New("invalid push gateway port")
		}
	}
	return nil
}
func ValidCredential(token string) bool {
	id, secret, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	a, e1 := base64.RawURLEncoding.Strict().DecodeString(id)
	b, e2 := base64.RawURLEncoding.Strict().DecodeString(secret)
	return e1 == nil && e2 == nil && len(a) == 16 && len(b) == 32
}
func ValidDevice(kind, token string) bool {
	switch kind {
	case "alert", "voip":
		return apnsToken.MatchString(token) && len(token)%2 == 0
	case "fcm":
		return len(token) <= 4096 && fcmToken.MatchString(token)
	default:
		return false
	}
}
func DeviceKind(kind string) string {
	if strings.HasPrefix(kind, "fcm_") {
		return "fcm"
	}
	return kind
}

type Registration struct {
	Kind  string `json:"kind"`
	Token string `json:"token"`
}
type RegistrationResult struct {
	ID string `json:"id"`
}
type Request struct {
	DeviceID string `json:"device_id"`
	Kind     string `json:"kind"`
	Event    Event  `json:"event"`
}
type Event struct {
	ServerID  string `json:"server_id"`
	ChatID    string `json:"chat_id"`
	MessageID string `json:"message_id,omitempty"`
	CallID    string `json:"call_id,omitempty"`
	Kind      string `json:"kind,omitempty"`
	State     string `json:"state,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

func (e Event) Payload(kind string, now time.Time) (json.RawMessage, error) {
	if !uuid.MatchString(e.ServerID) || !uuid.MatchString(e.ChatID) {
		return nil, errors.New("invalid routing identifiers")
	}
	p := map[string]any{"server_id": e.ServerID, "chat_id": e.ChatID}
	switch kind {
	case "alert", "fcm_message":
		if !uuid.MatchString(e.MessageID) || e.CallID != "" || e.Kind != "" || e.State != "" || e.ExpiresAt != 0 {
			return nil, errors.New("invalid message event")
		}
		p["message_id"] = e.MessageID
		if kind == "alert" {
			p["aps"] = map[string]any{"alert": map[string]string{"title": "FamilyChat", "body": "Новое сообщение"}, "sound": "default"}
		} else {
			p["sender_name"] = "FamilyChat"
		}
	case "voip", "fcm_call":
		if !uuid.MatchString(e.CallID) || e.MessageID != "" || (e.Kind != "audio" && e.Kind != "video") || e.State != "" || e.ExpiresAt <= now.Unix() || e.ExpiresAt > now.Unix()+60 {
			return nil, errors.New("invalid or expired call")
		}
		p["call_id"] = e.CallID
		p["kind"] = e.Kind
		p["caller_name"] = "FamilyChat"
		p["expires_at"] = e.ExpiresAt
		if kind == "voip" {
			p["aps"] = map[string]int{"content-available": 1}
		}
	case "fcm_call_state":
		if !uuid.MatchString(e.CallID) || e.MessageID != "" || e.Kind != "" || e.ExpiresAt != 0 {
			return nil, errors.New("invalid call state")
		}
		switch e.State {
		case "accepted", "rejected", "ended", "missed", "busy", "cancelled":
		default:
			return nil, errors.New("invalid call state")
		}
		p["call_id"] = e.CallID
		p["state"] = e.State
	default:
		return nil, errors.New("invalid push kind")
	}
	if strings.HasPrefix(kind, "fcm_") {
		p["client_server_id"] = e.ServerID
	}
	return json.Marshal(p)
}

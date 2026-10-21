package pushgateway

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrNotFound     = errors.New("not found")
	ErrQuota        = errors.New("device quota exceeded")
)

const maxStateBytes = 16 << 20
const maxDevices = 10000

type Device struct {
	ID       string `json:"id"`
	ClientID string `json:"client_id"`
	Kind     string `json:"kind"`
	Token    string `json:"token"`
	SeenAt   int64  `json:"seen_at"`
}
type clientRecord struct {
	Name string `json:"name"`
	Hash string `json:"token_hash"`
}
type diskState struct {
	Version int                     `json:"version"`
	Clients map[string]clientRecord `json:"clients"`
	Devices map[string]Device       `json:"devices"`
}

// Store uses a private directory and an OS lock shared with the administration CLI.
// Credentials are hashed; provider device tokens must remain readable for delivery.
type Store struct {
	path string
	mu   sync.Mutex
}

func Open(path string) (*Store, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("gateway state directory must have mode 0700")
	}
	s := &Store{path: path}
	err = s.withState(func(_ *diskState) (bool, error) { return false, nil })
	return s, err
}
func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func tokenHash(token string) string {
	v := sha256.Sum256([]byte(token))
	return hex.EncodeToString(v[:])
}
func (s *Store) withState(fn func(*diskState) (bool, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return errors.New("cannot open gateway state lock")
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	state := diskState{Version: 1, Clients: map[string]clientRecord{}, Devices: map[string]Device{}}
	f, err := os.Open(s.path)
	fresh := os.IsNotExist(err)
	if err != nil && !fresh {
		return errors.New("cannot read gateway state")
	}
	if !fresh {
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxStateBytes {
			return errors.New("invalid gateway state permissions or size")
		}
		dec := json.NewDecoder(io.LimitReader(f, maxStateBytes+1))
		dec.DisallowUnknownFields()
		if dec.Decode(&state) != nil || state.Version != 1 || state.Clients == nil || state.Devices == nil {
			return errors.New("invalid gateway state")
		}
		var tail any
		if dec.Decode(&tail) != io.EOF {
			return errors.New("invalid gateway state")
		}
	}
	dirty, err := fn(&state)
	if err != nil {
		return err
	}
	if !fresh && !dirty {
		return nil
	}
	data, err := json.Marshal(state)
	if err != nil || len(data) > maxStateBytes {
		return errors.New("gateway state size limit")
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".push-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	defer tmp.Close()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *Store) AddClient(name string) (string, error) {
	if strings.TrimSpace(name) == "" || len(name) > 100 {
		return "", errors.New("client name must be 1..100 bytes")
	}
	id := randomID(16)
	token := id + "." + randomID(32)
	err := s.withState(func(d *diskState) (bool, error) {
		if len(d.Clients) >= 1024 {
			return false, ErrQuota
		}
		d.Clients[id] = clientRecord{Name: name, Hash: tokenHash(token)}
		return true, nil
	})
	return token, err
}
func (s *Store) RevokeClient(id string) error {
	return s.withState(func(d *diskState) (bool, error) {
		if _, ok := d.Clients[id]; !ok {
			return false, ErrNotFound
		}
		delete(d.Clients, id)
		for key, v := range d.Devices {
			if v.ClientID == id {
				delete(d.Devices, key)
			}
		}
		return true, nil
	})
}
func (s *Store) Authenticate(token string) (string, error) {
	id, _, ok := strings.Cut(token, ".")
	if !ok || len(token) != 66 {
		return "", ErrUnauthorized
	}
	err := s.withState(func(d *diskState) (bool, error) {
		r, ok := d.Clients[id]
		if !ok || subtle.ConstantTimeCompare([]byte(r.Hash), []byte(tokenHash(token))) != 1 {
			return false, ErrUnauthorized
		}
		return false, nil
	})
	return id, err
}
func (s *Store) Register(clientID, kind, token string) (string, error) {
	var id string
	err := s.withState(func(d *diskState) (bool, error) {
		if _, ok := d.Clients[clientID]; !ok {
			return false, ErrUnauthorized
		}
		count := 0
		now := time.Now().Unix()
		for key, v := range d.Devices {
			if v.SeenAt < now-90*86400 {
				delete(d.Devices, key)
				continue
			}
			if v.ClientID == clientID {
				count++
				if v.Kind == kind && v.Token == token {
					id = key
					v.SeenAt = now
					d.Devices[key] = v
					return true, nil
				}
			}
		}
		if count >= 1000 || len(d.Devices) >= maxDevices {
			return false, ErrQuota
		}
		id = randomID(24)
		d.Devices[id] = Device{ID: id, ClientID: clientID, Kind: kind, Token: token, SeenAt: now}
		return true, nil
	})
	return id, err
}
func (s *Store) Device(clientID, id string) (Device, error) {
	var device Device
	err := s.withState(func(d *diskState) (bool, error) {
		if _, ok := d.Clients[clientID]; !ok {
			return false, ErrUnauthorized
		}
		v, ok := d.Devices[id]
		if !ok || v.ClientID != clientID {
			return false, ErrNotFound
		}
		device = v
		return false, nil
	})
	return device, err
}
func (s *Store) DeleteDevice(clientID, id string) error {
	return s.withState(func(d *diskState) (bool, error) {
		v, ok := d.Devices[id]
		if !ok || v.ClientID != clientID {
			return false, ErrNotFound
		}
		delete(d.Devices, id)
		return true, nil
	})
}

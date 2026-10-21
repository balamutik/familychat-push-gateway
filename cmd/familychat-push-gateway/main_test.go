package main

import (
	"bytes"
	"context"
	"github.com/balamutik/familychat-push-gateway/internal/pushgateway"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientAdministrationExportsPrivateCredentialAndRevokes(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "data", "state.json")
	tokenFile := filepath.Join(root, "family.token")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"add-client", "--state", state, "--name", "Family A", "--token-file", tokenFile}, &out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(data))
	if strings.Contains(out.String(), token) {
		t.Fatal("secret printed")
	}
	info, _ := os.Stat(tokenFile)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe token permissions")
	}
	store, err := pushgateway.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Authenticate(token)
	if err != nil {
		t.Fatal(err)
	}
	if err = run(context.Background(), []string{"add-client", "--state", state, "--name", "Family B", "--token-file", tokenFile}, &out); err == nil {
		t.Fatal("overwrote credential")
	}
	if err = run(context.Background(), []string{"revoke-client", "--state", state, "--id", id}, &out); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Authenticate(token); err == nil {
		t.Fatal("revocation failed")
	}
}
func TestServeRefusesMissingTLSBeforeListening(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"serve", "--state", filepath.Join(t.TempDir(), "state.json")}, &out); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("%v", err)
	}
}

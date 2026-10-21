package pushgateway

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestConcurrentAdministrationDoesNotLoseClientsOrPersistSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway", "state.json")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	credentials := make(chan string, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := a
			if i%2 == 1 {
				store = b
			}
			token, err := store.AddClient("family")
			if err != nil {
				t.Error(err)
				return
			}
			credentials <- token
		}(i)
	}
	wg.Wait()
	close(credentials)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for token := range credentials {
		if strings.Contains(string(data), token) {
			t.Fatal("raw auth credential persisted")
		}
		if _, err := a.Authenticate(token); err != nil {
			t.Fatal("client lost after concurrent write", err)
		}
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe state permissions")
	}
}
func TestUnsafeStateDirectoryRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "public")
	os.Mkdir(dir, 0755)
	if _, err := Open(filepath.Join(dir, "state.json")); err == nil {
		t.Fatal("world-readable directory accepted")
	}
}

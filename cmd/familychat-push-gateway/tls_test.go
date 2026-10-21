package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testBundle(t *testing.T, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"push.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})...)
}

func TestCertificateBundleStaysConsistentDuringAtomicRenewal(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tls.pem")
	bundles := [][]byte{testBundle(t, 1), testBundle(t, 2)}
	if err := os.WriteFile(path, bundles[0], 0600); err != nil {
		t.Fatal(err)
	}
	var writes sync.WaitGroup
	writes.Add(1)
	go func() {
		defer writes.Done()
		for i := 0; i < 500; i++ {
			if err := os.WriteFile(path+".next", bundles[i%2], 0600); err != nil {
				t.Error(err)
				return
			}
			if err := os.Rename(path+".next", path); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	defer writes.Wait()
	for i := 0; i < 500; i++ {
		if _, err := loadCertificate(path, path); err != nil {
			t.Fatalf("mixed or invalid TLS pair during renewal: %v", err)
		}
	}
}

func TestSeparateCertificateFilesRemainSupported(t *testing.T) {
	bundle := testBundle(t, 1)
	cert, rest := pem.Decode(bundle)
	key, _ := pem.Decode(rest)
	root := t.TempDir()
	certFile, keyFile := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(cert), 0600)
	os.WriteFile(keyFile, pem.EncodeToMemory(key), 0600)
	got, err := loadCertificate(certFile, keyFile)
	if err != nil || len(got.Certificate) != 1 {
		t.Fatalf("separate files: %v", err)
	}
	if _, err := tls.X509KeyPair(bundle, bundle); err != nil {
		t.Fatal(err)
	}
}

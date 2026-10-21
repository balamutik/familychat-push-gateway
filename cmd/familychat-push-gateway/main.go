// familychat-push-gateway is independent of the chat database and content keys.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/balamutik/familychat-push-gateway/internal/config"
	"github.com/balamutik/familychat-push-gateway/internal/push"
	"github.com/balamutik/familychat-push-gateway/internal/pushgateway"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func loadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	if certFile == keyFile {
		// Managed installs atomically replace one PEM bundle during renewal.
		// A single read prevents mixing a certificate with the previous key.
		data, err := os.ReadFile(certFile)
		if err != nil {
			return tls.Certificate{}, err
		}
		return tls.X509KeyPair(data, data)
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}
func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: familychat-push-gateway serve|add-client|revoke-client [options]")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(out)
	path := flags.String("state", "data/state.json", "Private gateway state (directory mode 0700)")
	listen := flags.String("listen", ":9443", "HTTPS listen address")
	cert := flags.String("tls-cert", "", "TLS certificate chain PEM")
	key := flags.String("tls-key", "", "TLS private key PEM")
	name := flags.String("name", "", "Client label for add-client")
	tokenFile := flags.String("token-file", "", "New private token export file for add-client")
	id := flags.String("id", "", "Client ID to revoke")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if args[0] == "serve" && (*cert == "" || *key == "") {
		return errors.New("TLS certificate and key are required")
	}
	switch args[0] {
	case "serve", "add-client", "revoke-client":
	default:
		return errors.New("unknown command")
	}
	store, err := pushgateway.Open(*path)
	if err != nil {
		return err
	}
	switch args[0] {
	case "add-client":
		if *tokenFile == "" {
			return errors.New("--token-file is required; credential is never printed")
		}
		f, err := os.OpenFile(*tokenFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("cannot create token file; choose a new path")
		}
		defer f.Close()
		token, err := store.AddClient(*name)
		if err != nil {
			os.Remove(*tokenFile)
			return err
		}
		clientID := strings.Split(token, ".")[0]
		if _, err = f.WriteString(token + "\n"); err == nil {
			err = f.Sync()
		}
		if err != nil {
			_ = store.RevokeClient(clientID)
			os.Remove(*tokenFile)
			return errors.New("cannot export client credential")
		}
		_, err = fmt.Fprintf(out, "Client ID: %s\nCredential saved to private token file.\n", clientID)
		return err
	case "revoke-client":
		if err := store.RevokeClient(*id); err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, "Client revoked; device registrations removed.")
		return err
	}
	c := config.Config{APNsKeyFile: os.Getenv("APNS_KEY_FILE"), APNsKeyID: os.Getenv("APNS_KEY_ID"), APNsTeamID: os.Getenv("APNS_TEAM_ID"), APNsTopic: os.Getenv("APNS_TOPIC"), FCMCredentialsFile: os.Getenv("FCM_CREDENTIALS_FILE"), FCMProjectID: os.Getenv("FCM_PROJECT_ID"), FCMApplicationID: os.Getenv("FCM_APPLICATION_ID")}
	if raw := os.Getenv("APNS_SANDBOX"); raw != "" {
		c.APNsSandbox, err = strconv.ParseBool(raw)
		if err != nil {
			return errors.New("APNS_SANDBOX must be boolean")
		}
	}
	sender, err := push.NewRouter(c)
	if err != nil {
		return errors.New("invalid gateway APNs/FCM configuration")
	}
	if sender == nil {
		return errors.New("configure at least one provider: APNs or FCM")
	}
	if _, err = loadCertificate(*cert, *key); err != nil {
		return errors.New("cannot load gateway TLS certificate and key")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		pair, err := loadCertificate(*cert, *key)
		return &pair, err
	}}
	server := &http.Server{Addr: *listen, Handler: pushgateway.NewHandler(store, sender, sender.APNs != nil, sender.FCM != nil), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		case <-done:
		}
	}()
	if err = server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("gateway HTTPS listener failed")
	}
	return nil
}

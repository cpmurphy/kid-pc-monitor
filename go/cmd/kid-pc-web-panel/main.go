// Command kid-pc-web-panel is the parent web panel: the browser UI on TCP
// 5000 and the reverse listener on TCP 9998 that kid agents connect to. It
// is a port of web_panel.main and runs on Windows, macOS and Linux.
//
//	kid-pc-web-panel [serve] [-background] [-log-file PATH] [-legacy-auth PATH]
//	kid-pc-web-panel set-secret   store the panel <-> agent shared secret
//	kid-pc-web-panel version
//
// It reads the same environment and files as the Python panel:
// KID_PC_MONITOR_HOST (0.0.0.0), KID_PC_MONITOR_PORT (5000),
// KID_PC_MONITOR_REVERSE_PORT (9998), KID_PC_MONITOR_SSL_CERT and
// KID_PC_MONITOR_SSL_KEY (else config_dir/tls/cert.pem and key.pem),
// KID_PC_MONITOR_SECRET (session key override), KID_PC_MONITOR_LOG_LEVEL,
// and config_dir()/panel.db, web_panel_auth.json and the secrets
// directories, so it can replace the Python panel in place.
//
// -background is for scheduled tasks and services: on Windows it hides the
// console window created for the launch, and it logs to -log-file (default
// config_dir()/web_panel.log, kept under 1 MiB by rolling to .1 at start).
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"kidpcmonitor/panel/auth"
	"kidpcmonitor/panel/reverse"
	"kidpcmonitor/panel/store"
	"kidpcmonitor/panel/web"
	"kidpcmonitor/secrets"
)

// version is set at release time with -X main.version=<tag>.
var version = "dev"

const minSecretLength = 8 // shared_secret.MIN_SECRET_LENGTH

func main() {
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		legacyAuth := fs.String("legacy-auth", "", "also read the password from this older web_panel_auth.json until a new one is saved")
		background := fs.Bool("background", false, "run unattended: hide a console window Windows created for this launch and log to a file")
		logFile := fs.String("log-file", "", "append the log to this file (default with -background: config_dir/web_panel.log)")
		_ = fs.Parse(args)
		if *background {
			hideOwnConsole()
			if *logFile == "" {
				*logFile = filepath.Join(secrets.ConfigDir(), "web_panel.log")
			}
		}
		err = serve(*legacyAuth, *logFile)
	case "set-secret":
		fs := flag.NewFlagSet("set-secret", flag.ExitOnError)
		replace := fs.Bool("replace", false, "prompt for a new secret even when one is stored")
		_ = fs.Parse(args)
		err = setSecret(os.Stdin, os.Stdout, *replace)
	case "version":
		fmt.Println(version)
	default:
		err = fmt.Errorf("unknown command %q (use serve, set-secret or version)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kid-pc-web-panel:", err)
		os.Exit(1)
	}
}

const maxLogBytes = 1 << 20

// openLog appends to path, first rolling a file over maxLogBytes to path.1.
func openLog(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if st, err := os.Stat(path); err == nil && st.Size() > maxLogBytes {
		os.Remove(path + ".1")
		os.Rename(path, path+".1")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
}

func logger(w io.Writer) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToUpper(strings.TrimSpace(os.Getenv("KID_PC_MONITOR_LOG_LEVEL"))) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARNING", "WARN":
		level = slog.LevelWarn
	case "ERROR", "CRITICAL":
		level = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// tlsCertPaths is paths.resolve_tls_cert_paths: both env paths, else the
// config dir's tls/cert.pem and key.pem, used only when both are readable
// files.
func tlsCertPaths() (cert, key string, ok bool) {
	cert, key = os.Getenv("KID_PC_MONITOR_SSL_CERT"), os.Getenv("KID_PC_MONITOR_SSL_KEY")
	if cert == "" || key == "" {
		dir := filepath.Join(secrets.ConfigDir(), "tls")
		cert, key = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	}
	for _, p := range []string{cert, key} {
		f, err := os.Open(p)
		if err != nil {
			return "", "", false
		}
		st, err := f.Stat()
		f.Close()
		if err != nil || !st.Mode().IsRegular() {
			return "", "", false
		}
	}
	return cert, key, true
}

// listenNetwork keeps an IPv4 literal (the default 0.0.0.0) IPv4-only, as
// the Python panel's AF_INET sockets are.
func listenNetwork(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		return "tcp4"
	}
	return "tcp"
}

func serve(legacyAuth, logFile string) error {
	var out io.Writer = os.Stdout
	logOut := io.Writer(os.Stderr)
	if logFile != "" {
		f, err := openLog(logFile)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		defer f.Close()
		out, logOut = f, f
	}
	log := logger(logOut)
	slog.SetDefault(log)
	host := envOr("KID_PC_MONITOR_HOST", "0.0.0.0")
	port, err := strconv.Atoi(envOr("KID_PC_MONITOR_PORT", "5000"))
	if err != nil {
		return fmt.Errorf("KID_PC_MONITOR_PORT: %w", err)
	}
	reversePort := reverse.ListenPort()

	st, err := store.Open(store.DefaultPath())
	if err != nil {
		return fmt.Errorf("open %s: %w", store.DefaultPath(), err)
	}
	defer st.Close()

	var tlsConfig *tls.Config
	cert, key, useTLS := tlsCertPaths()
	if useTLS {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	}

	files := auth.DefaultFiles()
	if legacyAuth != "" {
		files.Legacy = []string{legacyAuth}
	}
	rev := &reverse.Server{
		Addr: net.JoinHostPort(host, strconv.Itoa(reversePort)),
		TLS:  tlsConfig,
		Secret: func() (string, error) {
			s, err := secrets.LoadSharedSecret()
			if errors.Is(err, secrets.ErrNotFound) {
				return "", errors.New("no shared secret is configured; run kid-pc-web-panel set-secret")
			}
			return s, err
		},
		Logger: log,
	}
	app, err := web.New(web.Config{
		Store:         st,
		Auth:          files,
		Reverse:       web.ReverseServer{Server: rev},
		SecretKey:     os.Getenv("KID_PC_MONITOR_SECRET"),
		SecureCookies: useTLS,
		ReversePort:   reversePort,
		Logger:        log,
	})
	if err != nil {
		return err
	}
	rev.OnStatus = app.RecordReverseStatus
	rev.OnDisconnect = app.RecordReverseDisconnect

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen(listenNetwork(host), net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	if _, err := secrets.LoadSharedSecret(); err != nil {
		log.Warn("No shared secret is configured; agents cannot connect until you run kid-pc-web-panel set-secret")
	}
	go rev.ListenAndServe(ctx)
	go web.RunPruner(ctx, st, app)

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	fmt.Fprintf(out, "Kid PC Monitor web panel on %s://%s:%d\n", scheme, host, port)
	withTLS := ""
	if useTLS {
		withTLS = " with TLS"
	}
	fmt.Fprintf(out, "Agent reverse TCP on %s://%s:%d (native v3%s)\n", scheme, host, reversePort, withTLS)
	if useTLS {
		fmt.Fprintln(out, "TLS enabled. iOS Safari password autofill requires the certificate authority to be trusted on your phone.")
	}

	srv := &http.Server{
		Handler:           accessLog(log, app),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConfig,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	if useTLS {
		err = srv.ServeTLS(ln, "", "")
	} else {
		err = srv.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// accessLog logs one line per request, as Flask's development server does.
func accessLog(log *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rec, r)
		log.Info(fmt.Sprintf("%s %s %s", r.Method, r.URL.RequestURI(), strconv.Itoa(rec.status)), "client", r.RemoteAddr)
	})
}

// setSecret is shared_secret.prompt_and_store_shared_secret: reuse a stored
// secret (re-saving it to the preferred directory), else prompt twice.
// Without a terminal it reads the secret, then its confirmation, one per
// line from in, so installers can pipe it.
func setSecret(in io.Reader, out io.Writer, replace bool) error {
	if !replace {
		if existing, err := secrets.LoadSharedSecret(); err == nil {
			source := secrets.FindPath(secrets.SharedSecretName)
			dest, err := secrets.SaveSharedSecret(existing)
			if err != nil {
				return err
			}
			if source != "" && source != dest {
				fmt.Fprintf(out, "Reusing existing shared secret from %s (also saved to %s).\n", source, dest)
			} else {
				fmt.Fprintf(out, "Reusing existing shared secret from %s.\n", dest)
			}
			return nil
		}
	}
	fmt.Fprintln(out, "Shared secret (web panel <-> monitoring agent)")
	fmt.Fprintln(out, "  Enter the SAME secret here and when you install the agent on the kid's PC.")
	fmt.Fprintln(out, "  A random string from a password manager is best; otherwise a short phrase of a")
	fmt.Fprintln(out, "  few unrelated words that you do not use anywhere else.")
	read := lineReader(in, out)
	for {
		secret, err := read("Enter shared secret: ")
		if err != nil {
			return fmt.Errorf("cancelled; shared secret not changed (%w)", err)
		}
		secret = strings.TrimSpace(secret)
		if len([]rune(secret)) < minSecretLength {
			fmt.Fprintf(out, "  Too short: use at least %d characters.\n", minSecretLength)
			continue
		}
		confirm, err := read("Re-enter to confirm: ")
		if err != nil {
			return fmt.Errorf("cancelled; shared secret not changed (%w)", err)
		}
		if strings.TrimSpace(confirm) != secret {
			fmt.Fprintln(out, "  Entries did not match. Please try again.")
			continue
		}
		path, err := secrets.SaveSharedSecret(secret)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Shared secret saved (encrypted at rest) at %s.\n", path)
		return nil
	}
}

// lineReader reads without echo from a terminal, else line by line.
func lineReader(in io.Reader, out io.Writer) func(prompt string) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return func(prompt string) (string, error) {
			fmt.Fprint(out, prompt)
			b, err := term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(out)
			return string(b), err
		}
	}
	br := bufio.NewReader(in)
	return func(prompt string) (string, error) {
		fmt.Fprint(out, prompt)
		line, err := br.ReadString('\n')
		fmt.Fprintln(out)
		if err != nil && line == "" {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
}

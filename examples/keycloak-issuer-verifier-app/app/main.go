package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type config struct {
	AppHost                string
	AppPort                string
	AppBaseURL             string
	WalletUIURL            string
	KeycloakBaseURL        string
	KeycloakCACert         string
	KeycloakRealm          string
	OID4VCICredentialScope string
	AppClientID            string
	AppRedirectURI         string
	KeycloakTrustListPath  string
}

type authSession struct {
	Verifier  string
	Mode      string
	CreatedAt time.Time
}

type appSession struct {
	CreatedAt         time.Time
	LoginMethod       string
	IDToken           string
	AccessToken       string
	RefreshToken      string
	IDTokenClaims     map[string]any
	AccessTokenClaims map[string]any
}

type server struct {
	cfg          config
	authMu       sync.Mutex
	authSessions map[string]authSession
	appMu        sync.Mutex
	appSessions  map[string]appSession
}

func loadConfig() config {
	appHost := getenvDefault("APP_HOST", "127.0.0.1")
	appPort := getenvDefault("APP_PORT", "8090")
	appBaseURL := getenvDefault("APP_BASE_URL", fmt.Sprintf("http://%s:%s", appHost, appPort))
	return config{
		AppHost:                appHost,
		AppPort:                appPort,
		AppBaseURL:             appBaseURL,
		WalletUIURL:            getenvDefault("WALLET_UI_URL", "http://localhost:8085/"),
		KeycloakBaseURL:        getenvDefault("KEYCLOAK_BASE_URL", "http://localhost:8080"),
		KeycloakCACert:         os.Getenv("KEYCLOAK_CA_CERT"),
		KeycloakRealm:          getenvDefault("KEYCLOAK_REALM", "wallet-app-demo"),
		OID4VCICredentialScope: getenvDefault("OID4VCI_CREDENTIAL_SCOPE", "membership-credential"),
		AppClientID:            getenvDefault("APP_CLIENT_ID", "wallet-app"),
		AppRedirectURI:         getenvDefault("APP_REDIRECT_URI", appBaseURL+"/callback"),
		KeycloakTrustListPath:  os.Getenv("KEYCLOAK_TRUST_LIST_PATH"),
	}
}

func getenvDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func newServer(cfg config) *server {
	return &server{
		cfg:          cfg,
		authSessions: map[string]authSession{},
		appSessions:  map[string]appSession{},
	}
}

func (s *server) httpClient() (*http.Client, error) {
	transport := &http.Transport{}
	if s.cfg.KeycloakCACert != "" {
		caBytes, err := os.ReadFile(s.cfg.KeycloakCACert)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if ok := pool.AppendCertsFromPEM(caBytes); !ok {
			return nil, fmt.Errorf("failed to load CA certificate %s", s.cfg.KeycloakCACert)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: transport}, nil
}

func (s *server) keycloakRealmURL() string {
	return s.cfg.KeycloakBaseURL + "/realms/" + s.cfg.KeycloakRealm
}

func (s *server) jsonRequest(method, rawURL string, body any, headers map[string]string) (map[string]any, error) {
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, rawURL, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	client, err := s.httpClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s failed (%d): %s", method, rawURL, resp.StatusCode, string(respBody))
	}
	if len(respBody) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *server) formRequest(rawURL string, values url.Values) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client, err := s.httpClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %s failed (%d): %s", rawURL, resp.StatusCode, string(respBody))
	}
	if len(respBody) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func randomToken(size int) string {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func pkcePair() (string, string) {
	verifier := randomToken(48)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func decodeJWTPayload(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return map[string]any{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func (s *server) createOfferURI(accessToken string) (string, error) {
	offerURL := fmt.Sprintf(
		"%s/protocol/oid4vc/create-credential-offer?credential_configuration_id=%s&pre_authorized=true&type=uri",
		s.keycloakRealmURL(),
		url.QueryEscape(s.cfg.OID4VCICredentialScope),
	)
	offerData, err := s.jsonRequest(http.MethodGet, offerURL, nil, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	if err != nil {
		return "", err
	}
	issuer, _ := offerData["issuer"].(string)
	nonce, _ := offerData["nonce"].(string)
	rawOfferURI := issuer + "/" + nonce
	return "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(rawOfferURI), nil
}

func (s *server) createLoginURL(mode string) (string, error) {
	if mode != "login" && mode != "password" && mode != "wallet" {
		return "", fmt.Errorf("unsupported login mode: %s", mode)
	}
	state := "s-" + randomToken(8)
	nonce := "n-" + randomToken(8)
	verifier, challenge := pkcePair()

	s.authMu.Lock()
	s.authSessions[state] = authSession{
		Verifier:  verifier,
		Mode:      mode,
		CreatedAt: time.Now(),
	}
	s.authMu.Unlock()

	values := url.Values{
		"client_id":             {s.cfg.AppClientID},
		"redirect_uri":          {s.cfg.AppRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if mode == "wallet" {
		values.Set("kc_idp_hint", "oid4vp")
		values.Set("prompt", "login")
	}
	return s.keycloakRealmURL() + "/protocol/openid-connect/auth?" + values.Encode(), nil
}

func (s *server) exchangeCode(code, state string) (map[string]any, error) {
	s.authMu.Lock()
	authSession, ok := s.authSessions[state]
	if ok {
		delete(s.authSessions, state)
	}
	s.authMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown or expired state: %s", state)
	}

	tokenData, err := s.formRequest(s.keycloakRealmURL()+"/protocol/openid-connect/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {s.cfg.AppClientID},
		"redirect_uri":  {s.cfg.AppRedirectURI},
		"code":          {code},
		"code_verifier": {authSession.Verifier},
	})
	if err != nil {
		return nil, err
	}
	return tokenData, nil
}

func (s *server) cleanupSessions() {
	cutoff := time.Now().Add(-1 * time.Hour)

	s.authMu.Lock()
	for key, value := range s.authSessions {
		if value.CreatedAt.Before(cutoff) {
			delete(s.authSessions, key)
		}
	}
	s.authMu.Unlock()

	s.appMu.Lock()
	for key, value := range s.appSessions {
		if value.CreatedAt.Before(cutoff) {
			delete(s.appSessions, key)
		}
	}
	s.appMu.Unlock()
}

func (s *server) currentAppSession(r *http.Request) (appSession, bool) {
	cookie, err := r.Cookie("demo_session")
	if err != nil {
		return appSession{}, false
	}
	s.appMu.Lock()
	session, ok := s.appSessions[cookie.Value]
	s.appMu.Unlock()
	return session, ok
}

func page(title, body string) string {
	markup := `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>__TITLE__</title>
  <style>
    :root {
      --bg: #f4efe6;
      --paper: #fffaf2;
      --ink: #1f2a1f;
      --muted: #5b655b;
      --line: #d6cdbf;
      --accent: #0d6b57;
      --accent-2: #d97f2f;
      --shadow: 0 24px 60px rgba(55, 44, 24, 0.14);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(217, 127, 47, 0.16), transparent 36%),
        radial-gradient(circle at bottom right, rgba(13, 107, 87, 0.16), transparent 34%),
        linear-gradient(180deg, #efe6d5, var(--bg));
      min-height: 100vh;
    }
    main {
      max-width: 980px;
      margin: 0 auto;
      padding: 40px 20px 56px;
    }
    .hero {
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 28px;
      box-shadow: var(--shadow);
      padding: 28px;
    }
    .eyebrow {
      text-transform: uppercase;
      letter-spacing: 0.18em;
      font-size: 12px;
      color: var(--muted);
      margin-bottom: 10px;
    }
    h1, h2 {
      margin: 0 0 12px;
      font-weight: 600;
    }
    p {
      margin: 0 0 16px;
      line-height: 1.55;
      color: var(--muted);
    }
    .grid {
      display: grid;
      gap: 18px;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      margin-top: 24px;
    }
    .panel {
      background: rgba(255, 250, 242, 0.9);
      border: 1px solid var(--line);
      border-radius: 22px;
      padding: 20px;
    }
    .cta {
      display: inline-block;
      margin-top: 10px;
      margin-right: 10px;
      padding: 12px 16px;
      border-radius: 999px;
      text-decoration: none;
      color: white;
      background: linear-gradient(135deg, var(--accent), #145f99);
      font-weight: 600;
    }
    button.cta {
      border: 0;
      cursor: pointer;
      font: inherit;
    }
    .secondary {
      background: linear-gradient(135deg, var(--accent-2), #b45424);
    }
    .muted {
      background: linear-gradient(135deg, #5e705f, #475549);
    }
    form.inline {
      display: inline;
    }
    code, pre {
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      font-size: 14px;
    }
    pre {
      margin: 14px 0 0;
      padding: 14px;
      background: #f7f0e5;
      border: 1px solid var(--line);
      border-radius: 16px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      color: var(--ink);
    }
    .note {
      margin-top: 18px;
      font-size: 14px;
    }
  </style>
</head>
<body>
<main>
__BODY__
</main>
</body>
</html>`
	markup = strings.Replace(markup, "__TITLE__", html.EscapeString(title), 1)
	markup = strings.Replace(markup, "__BODY__", body, 1)
	return markup
}

func (s *server) writeJSON(w http.ResponseWriter, status int, payload any) {
	body, _ := json.MarshalIndent(payload, "", "  ")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *server) writeHTML(w http.ResponseWriter, status int, markup string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, markup)
}

func (s *server) writeError(w http.ResponseWriter, message string, status int) {
	s.writeHTML(w, status, page("Error", fmt.Sprintf(`
<section class="hero">
  <div class="eyebrow">Error</div>
  <h1>Request failed.</h1>
  <pre>%s</pre>
  <p class="note"><a href="/">Back to the demo app</a></p>
</section>`, html.EscapeString(message))))
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.cleanupSessions()

	defer func() {
		if recovered := recover(); recovered != nil {
			s.writeError(w, fmt.Sprintf("%v", recovered), http.StatusInternalServerError)
		}
	}()

	switch r.URL.Path {
	case "/":
		s.handleHome(w, r)
	case "/healthz":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	case "/api/login-url":
		s.handleAPILoginURL(w, r)
	case "/api/credential-offer":
		s.handleAPICredentialOffer(w, r)
	case "/keycloak-trustlist.jwt":
		s.handleTrustList(w, r)
	case "/login":
		s.redirectToLogin(w, r, "login")
	case "/login/password":
		s.redirectToLogin(w, r, "password")
	case "/login/wallet":
		s.redirectToLogin(w, r, "wallet")
	case "/issue":
		s.handleIssue(w, r)
	case "/logout":
		s.handleLogout(w, r)
	case "/callback":
		s.handleCallback(w, r)
	default:
		s.writeHTML(w, http.StatusNotFound, page("Not Found", `<section class="hero"><h1>Not found.</h1></section>`))
	}
}

func (s *server) handleHome(w http.ResponseWriter, r *http.Request) {
	appSession, ok := s.currentAppSession(r)
	if !ok {
		s.writeHTML(w, http.StatusOK, page("Keycloak Issuance and Verification Demo", fmt.Sprintf(`
<section class="hero">
  <h1>Keycloak issuer + verifier demo</h1>
  <p>Sign in, issue a credential, then sign in again with the wallet.</p>
  <div class="grid">
    <section class="panel">
      <h2>Start</h2>
      <p>Use <code>alice</code> / <code>alice</code>.</p>
      <a class="cta secondary" href="/login">Sign In</a>
      <pre>curl -fsS %s/api/login-url?mode=password</pre>
    </section>
  </div>
</section>`, s.cfg.AppBaseURL)))
		return
	}

	idClaims, _ := json.MarshalIndent(appSession.IDTokenClaims, "", "  ")
	accessClaims, _ := json.MarshalIndent(appSession.AccessTokenClaims, "", "  ")
	s.writeHTML(w, http.StatusOK, page("Keycloak Issuance and Verification Demo", fmt.Sprintf(`
<section class="hero">
  <h1>Signed in with %s</h1>
  <p>Issue a credential, then log out and sign in again through Keycloak.</p>
  <form action="/issue" method="post" style="display:inline">
    <button class="cta secondary" type="submit">Issue Membership Credential</button>
  </form>
  <a class="cta muted" href="%s">Open Wallet UI</a>
  <a class="cta muted" href="/logout">Logout</a>
  <div class="grid">
    <section class="panel">
      <h2>ID Token Claims</h2>
      <pre id="id-token-claims">%s</pre>
    </section>
    <section class="panel">
      <h2>Access Token Claims</h2>
      <pre>%s</pre>
    </section>
  </div>
</section>`, html.EscapeString(appSession.LoginMethod), html.EscapeString(s.cfg.WalletUIURL), html.EscapeString(string(idClaims)), html.EscapeString(string(accessClaims)))))
}

func (s *server) handleAPILoginURL(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "login"
	}
	loginURL, err := s.createLoginURL(mode)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"login_url": loginURL, "mode": mode})
}

func (s *server) handleAPICredentialOffer(w http.ResponseWriter, r *http.Request) {
	appSession, ok := s.currentAppSession(r)
	if !ok {
		s.writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login_required"})
		return
	}
	offerURI, err := s.createOfferURI(appSession.AccessToken)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"offer_uri": offerURI})
}

func (s *server) handleTrustList(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.cfg.KeycloakTrustListPath) == "" {
		s.writeHTML(w, http.StatusNotFound, page("Not Found", `<section class="hero"><h1>Not found.</h1></section>`))
		return
	}
	raw, err := os.ReadFile(s.cfg.KeycloakTrustListPath)
	if err != nil {
		s.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	_, _ = io.WriteString(w, strings.TrimSpace(string(raw)))
}

func (s *server) redirectToLogin(w http.ResponseWriter, r *http.Request, mode string) {
	loginURL, err := s.createLoginURL(mode)
	if err != nil {
		s.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (s *server) handleIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		s.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appSession, ok := s.currentAppSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		s.writeHTML(w, http.StatusOK, page("Issue Credential", fmt.Sprintf(`
<section class="hero">
  <h1>Create credential offer</h1>
  <p>This generates a new offer for the current session.</p>
  <form action="/issue" method="post" style="display:inline">
    <button class="cta secondary" type="submit">Create Offer</button>
  </form>
  <a class="cta muted" href="%s">Open Wallet UI</a>
  <p class="note"><a href="/">Back to the demo app</a></p>
</section>`, html.EscapeString(s.cfg.WalletUIURL))))
		return
	}

	offerURI, err := s.createOfferURI(appSession.AccessToken)
	if err != nil {
		s.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	safeURI := html.EscapeString(offerURI)
	acceptCommand := html.EscapeString("oid4vc-dev wallet accept '" + offerURI + "'")
	s.writeHTML(w, http.StatusOK, page("Issue Credential", fmt.Sprintf(`
<section class="hero">
  <h1>Credential offer</h1>
  <p>Open it in the wallet or redeem it with the CLI.</p>
  <a class="cta secondary" href="%s">Open Offer In Wallet</a>
  <a class="cta muted" href="%s">Open Wallet UI</a>
  <pre>%s</pre>
  <pre>%s</pre>
  <p class="note"><a href="/">Back to the demo app</a></p>
</section>`, safeURI, html.EscapeString(s.cfg.WalletUIURL), acceptCommand, safeURI)))
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var session appSession
	var ok bool
	if cookie, err := r.Cookie("demo_session"); err == nil {
		s.appMu.Lock()
		session, ok = s.appSessions[cookie.Value]
		delete(s.appSessions, cookie.Value)
		s.appMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "demo_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	values := url.Values{
		"post_logout_redirect_uri": {s.cfg.AppBaseURL},
		"client_id":                {s.cfg.AppClientID},
	}
	if session.IDToken != "" {
		values.Set("id_token_hint", session.IDToken)
	}
	http.Redirect(w, r, s.keycloakRealmURL()+"/protocol/openid-connect/logout?"+values.Encode(), http.StatusFound)
}

func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if errValue := r.URL.Query().Get("error"); errValue != "" {
		description := r.URL.Query().Get("error_description")
		s.writeHTML(w, http.StatusBadRequest, page("Login Failed", fmt.Sprintf(`
<section class="hero">
  <h1>Login failed</h1>
  <pre>%s
%s</pre>
  <p class="note"><a href="/">Back to the demo app</a></p>
</section>`, html.EscapeString(errValue), html.EscapeString(description))))
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		s.writeHTML(w, http.StatusBadRequest, page("Missing Authorization Response", `<section class="hero"><h1>Missing code or state.</h1></section>`))
		return
	}

	tokenData, err := s.exchangeCode(code, state)
	if err != nil {
		s.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	accessToken, _ := tokenData["access_token"].(string)
	refreshToken, _ := tokenData["refresh_token"].(string)
	idToken, _ := tokenData["id_token"].(string)
	accessClaims := decodeJWTPayload(accessToken)
	loginType, _ := accessClaims["login_type"].(string)
	if loginType == "" {
		loginType = "unknown"
	}

	sessionID := "app-" + randomToken(12)
	s.appMu.Lock()
	s.appSessions[sessionID] = appSession{
		CreatedAt:         time.Now(),
		LoginMethod:       loginType,
		IDToken:           idToken,
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
		IDTokenClaims:     decodeJWTPayload(idToken),
		AccessTokenClaims: accessClaims,
	}
	s.appMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "demo_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func main() {
	cfg := loadConfig()
	srv := newServer(cfg)
	addr := cfg.AppHost + ":" + cfg.AppPort
	log.Printf("Serving demo app on %s", cfg.AppBaseURL)
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatal(err)
	}
}

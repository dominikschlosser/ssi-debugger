package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Config holds the configuration for the debugging reverse proxy.
type Config struct {
	TargetURL     *url.URL
	ProxyPort     int
	DashboardPort int
	NoDashboard   bool
}

// Server is the OID4VP/VCI debugging reverse proxy.
type Server struct {
	config   Config
	store    *Store
	rewriter *Rewriter
	proxy    *httputil.ReverseProxy
}

// NewServer creates a new debugging reverse proxy server.
func NewServer(cfg Config) *Server {
	s := &Server{
		config: cfg,
		store:  NewStore(1000),
	}

	proxyHost := fmt.Sprintf("localhost:%d", cfg.ProxyPort)
	targetHost := cfg.TargetURL.Host
	s.rewriter = NewRewriter(targetHost, proxyHost)

	s.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = cfg.TargetURL.Scheme
			req.URL.Host = cfg.TargetURL.Host
			req.Host = cfg.TargetURL.Host
		},
		ModifyResponse: s.modifyResponse,
	}

	return s
}

// Store returns the traffic store for use by the dashboard.
func (s *Server) Store() *Store {
	return s.store
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Capture request body
	var reqBody string
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {
			reqBody = string(bodyBytes)
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	// Store request info in context via header (cleaned up in modifyResponse)
	r.Header.Set("X-Proxy-Start", fmt.Sprintf("%d", start.UnixNano()))
	r.Header.Set("X-Proxy-ReqBody", reqBody)

	s.proxy.ServeHTTP(w, r)
}

func (s *Server) modifyResponse(resp *http.Response) error {
	start := time.Now()
	if ts := resp.Request.Header.Get("X-Proxy-Start"); ts != "" {
		var ns int64
		fmt.Sscanf(ts, "%d", &ns)
		start = time.Unix(0, ns)
	}
	reqBody := resp.Request.Header.Get("X-Proxy-ReqBody")

	// Clean up internal headers
	resp.Request.Header.Del("X-Proxy-Start")
	resp.Request.Header.Del("X-Proxy-ReqBody")

	// Read response body
	var respBody string
	if resp.Body != nil {
		var reader io.ReadCloser
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			gz, err := gzip.NewReader(resp.Body)
			if err == nil {
				reader = gz
				resp.Header.Del("Content-Encoding")
				resp.Header.Del("Content-Length")
			} else {
				reader = resp.Body
			}
		default:
			reader = resp.Body
		}

		bodyBytes, err := io.ReadAll(reader)
		reader.Close()
		if err == nil {
			respBody = string(bodyBytes)

			// Rewrite URLs in response
			contentType := resp.Header.Get("Content-Type")
			rewritten := s.rewriter.RewriteBody(respBody, contentType)
			s.rewriter.RewriteHeaders(resp.Header)

			resp.Body = io.NopCloser(strings.NewReader(rewritten))
			resp.ContentLength = int64(len(rewritten))
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
		}
	}

	duration := time.Since(start)

	entry := &TrafficEntry{
		Timestamp:       start,
		Method:          resp.Request.Method,
		URL:             resp.Request.URL.String(),
		RequestHeaders:  resp.Request.Header.Clone(),
		RequestBody:     reqBody,
		StatusCode:      resp.StatusCode,
		ResponseHeaders: resp.Header.Clone(),
		ResponseBody:    respBody,
		Duration:        duration,
		DurationMS:      duration.Milliseconds(),
	}

	Classify(entry)
	s.store.Add(entry)
	PrintEntry(entry)

	return nil
}

package service

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// IBKR's SSO bundle computes the cookie domain by dropping the first hostname
// label. For primary.localhost this becomes .localhost, which browsers reject.
// On real domains it also shares login cookies between Gateway instances.
// Prepend a host-only cookie adapter before the vendor code runs; rewriting
// Set-Cookie headers alone cannot affect document.cookie assignments.
const gatewaySSOBundlePath = "/sso/lib/xyz.bundle.min.js"

//go:embed web/gateway-cookie-scope.js
var gatewayCookieScopeScript []byte

func loginCompletionNotifier(manager Gateway) func() {
	if observer, ok := manager.(interface{ NotifyLoginComplete() }); ok {
		return observer.NotifyLoginComplete
	}
	return nil
}

// Dispatcher responses merely signal login progress and wake the supervisor.
// Only a server-side SSO validation inside an explicit login window permits init;
// no particular vendor page body or success message is required.
func observeGatewayLogin(resp *http.Response, notify func()) error {
	if notify != nil && resp.Request.URL.Path == "/sso/Dispatcher" &&
		(resp.Request.Method == http.MethodGet || resp.Request.Method == http.MethodPost) &&
		(resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound) &&
		resp.Request.Context().Err() == nil {
		notify()
	}
	return nil
}

func prepareGatewaySSOScript(req *http.Request) {
	if req.Method != http.MethodGet || req.URL.Path != gatewaySSOBundlePath {
		return
	}
	// Always obtain a full representation that can be transformed. A browser
	// hard refresh may be needed once after upgrading from an unpatched bundle.
	req.Header.Set("Accept-Encoding", "identity")
	for _, name := range []string{"If-None-Match", "If-Modified-Since", "Range", "If-Range"} {
		req.Header.Del(name)
	}
}

func rewriteGatewaySSOScript(resp *http.Response) error {
	if resp.Request.Method != http.MethodGet || resp.Request.URL.Path != gatewaySSOBundlePath || resp.StatusCode != http.StatusOK {
		return nil
	}
	contentType := strings.ToLower(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	if contentType != "application/javascript" && contentType != "text/javascript" && contentType != "application/x-javascript" {
		return nil
	}
	defer resp.Body.Close()
	var reader io.Reader = resp.Body
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		decoded, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("decode Gateway SSO script: %w", err)
		}
		defer decoded.Close()
		reader = decoded
	default:
		return fmt.Errorf("unsupported Gateway SSO script encoding")
	}
	const maxScriptSize = 8 << 20
	body, err := io.ReadAll(io.LimitReader(reader, maxScriptSize+1))
	if err != nil {
		return fmt.Errorf("read Gateway SSO script: %w", err)
	}
	if len(body) > maxScriptSize {
		return fmt.Errorf("Gateway SSO script exceeds size limit")
	}
	body = append(append([]byte{}, gatewayCookieScopeScript...), body...)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Cache-Control", "no-store")
	for _, name := range []string{"Content-Encoding", "ETag", "Last-Modified", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "Accept-Ranges"} {
		resp.Header.Del(name)
	}
	return nil
}

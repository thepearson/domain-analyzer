package analyzer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveRedirectLocationAndSingleMeasure(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/step1":
			w.Header().Set("Server", "EdgeGateway")
			http.Redirect(w, r, "/step2", http.StatusMovedPermanently)
		case "/step2":
			w.Header().Set("Server", "AppOrigin")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("hello world"))
		}
	}))
	defer srv.Close()

	hop1, _, err := measureSingleHTTPRequest(srv.URL + "/step1")
	if err != nil {
		t.Fatalf("measureSingleHTTPRequest step1 failed: %v", err)
	}
	if hop1.StatusCode != http.StatusMovedPermanently || hop1.Location != "/step2" || hop1.Server != "EdgeGateway" {
		t.Errorf("unexpected hop1: %+v", hop1)
	}

	nextURL, err := resolveRedirectLocation(hop1.URL, hop1.Location)
	if err != nil || nextURL != srv.URL+"/step2" {
		t.Fatalf("expected resolved URL %s/step2, got %q (err=%v)", srv.URL, nextURL, err)
	}

	hop2, wf2, err := measureSingleHTTPRequest(nextURL)
	if err != nil {
		t.Fatalf("measureSingleHTTPRequest step2 failed: %v", err)
	}
	if hop2.StatusCode != http.StatusOK || wf2.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 on hop2, got %+v / %+v", hop2, wf2)
	}
}

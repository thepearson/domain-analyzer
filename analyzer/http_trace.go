package analyzer

import (
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

type HTTPRedirectHop struct {
	Step       int     `json:"step"`
	URL        string  `json:"url"`
	StatusCode int     `json:"status_code"`
	Status     string  `json:"status"`
	Location   string  `json:"location,omitempty"`
	Server     string  `json:"server,omitempty"`
	Protocol   string  `json:"protocol,omitempty"`
	TotalMs    float64 `json:"total_ms"`
}

type HTTPWaterfallTiming struct {
	URL               string  `json:"url"`
	Protocol          string  `json:"protocol,omitempty"`
	StatusCode        int     `json:"status_code"`
	DNSMs             float64 `json:"dns_ms"`
	TCPConnectMs      float64 `json:"tcp_connect_ms"`
	TLSHandshakeMs    float64 `json:"tls_handshake_ms"`
	TTFBMs            float64 `json:"ttfb_ms"`
	ContentTransferMs float64 `json:"content_transfer_ms"`
	TotalMs           float64 `json:"total_ms"`
}

type HTTPTraceResult struct {
	InitialURL      string              `json:"initial_url"`
	FinalURL        string              `json:"final_url"`
	FinalStatus     int                 `json:"final_status"`
	UpgradedHTTPS   bool                `json:"upgraded_https"`
	RedirectCount   int                 `json:"redirect_count"`
	TotalChainMs    float64             `json:"total_chain_ms"`
	Hops            []HTTPRedirectHop   `json:"hops,omitempty"`
	Waterfall       HTTPWaterfallTiming `json:"waterfall"`
	DiscoveredHosts []string            `json:"discovered_hosts,omitempty"`
	Error           string              `json:"error,omitempty"`
}

func roundMs(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return math.Round(float64(d.Microseconds())/10.0) / 100.0
}

// TraceHTTPChain traces the full HTTP -> HTTPS redirect chain step-by-step and records
// a detailed phase-by-phase performance timing waterfall (DNS, TCP, TLS, TTFB, Transfer).
func TraceHTTPChain(target string) *HTTPTraceResult {
	clean := NormalizeTarget(target)
	if clean == "" {
		return &HTTPTraceResult{Error: "Invalid target"}
	}

	startURL := "http://" + clean
	res := &HTTPTraceResult{
		InitialURL: startURL,
	}

	seenHosts := make(map[string]bool)
	recordHost := func(rawURL string) {
		if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
			h := strings.ToLower(u.Hostname())
			if h != strings.ToLower(clean) && !seenHosts[h] {
				seenHosts[h] = true
				res.DiscoveredHosts = append(res.DiscoveredHosts, h)
			}
		}
	}

	currentURL := startURL
	const maxHops = 10
	var lastWaterfall HTTPWaterfallTiming

	for step := 1; step <= maxHops; step++ {
		hop, wf, err := measureSingleHTTPRequest(currentURL)
		if err != nil {
			// If initial http:// connection failed on step 1, try https:// directly
			if step == 1 && strings.HasPrefix(currentURL, "http://") {
				currentURL = "https://" + clean
				res.InitialURL = currentURL
				hop, wf, err = measureSingleHTTPRequest(currentURL)
			}
			if err != nil {
				if len(res.Hops) == 0 {
					res.Error = err.Error()
				}
				break
			}
		}

		hop.Step = step
		res.Hops = append(res.Hops, hop)
		res.TotalChainMs = math.Round((res.TotalChainMs+hop.TotalMs)*100) / 100
		res.FinalURL = hop.URL
		res.FinalStatus = hop.StatusCode
		lastWaterfall = wf
		recordHost(hop.URL)

		if hop.StatusCode >= 300 && hop.StatusCode < 400 && hop.Location != "" {
			res.RedirectCount++
			nextURL, err := resolveRedirectLocation(hop.URL, hop.Location)
			if err != nil || nextURL == "" {
				break
			}
			recordHost(nextURL)
			currentURL = nextURL
			continue
		}
		break
	}

	if strings.HasPrefix(strings.ToLower(res.InitialURL), "http://") &&
		strings.HasPrefix(strings.ToLower(res.FinalURL), "https://") {
		res.UpgradedHTTPS = true
	}

	// If the final URL stayed on plain http:// (no redirect to https://), check if https:// is also available
	// so the waterfall includes TLS handshake timing when supported.
	if strings.HasPrefix(strings.ToLower(lastWaterfall.URL), "http://") {
		httpsURL := "https://" + clean
		if _, httpsWF, err := measureSingleHTTPRequest(httpsURL); err == nil && httpsWF.StatusCode > 0 {
			lastWaterfall = httpsWF
		}
	}

	res.Waterfall = lastWaterfall
	return res
}

func resolveRedirectLocation(baseURL, location string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return "", err
	}
	return base.ResolveReference(ref).String(), nil
}

func measureSingleHTTPRequest(targetURL string) (HTTPRedirectHop, HTTPWaterfallTiming, error) {
	var (
		dnsStart, dnsDone   time.Time
		connStart, connDone time.Time
		tlsStart, tlsDone   time.Time
		wroteReq, firstByte time.Time
	)

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			dnsDone = time.Now()
		},
		ConnectStart: func(_, _ string) {
			if connStart.IsZero() {
				connStart = time.Now()
			}
		},
		ConnectDone: func(_, _ string, _ error) {
			if connDone.IsZero() {
				connDone = time.Now()
			}
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			tlsDone = time.Now()
		},
		WroteRequest: func(_ httptrace.WroteRequestInfo) {
			wroteReq = time.Now()
		},
		GotFirstResponseByte: func() {
			firstByte = time.Now()
		},
	}

	transport := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return HTTPRedirectHop{}, HTTPWaterfallTiming{}, err
	}
	req.Header.Set("User-Agent", wafUserAgent)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	reqStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return HTTPRedirectHop{}, HTTPWaterfallTiming{}, err
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256*1024))
	reqEnd := time.Now()

	var dnsDur, tcpDur, tlsDur, ttfbDur, transferDur time.Duration
	if !dnsStart.IsZero() && !dnsDone.IsZero() {
		dnsDur = dnsDone.Sub(dnsStart)
	}
	if !connStart.IsZero() && !connDone.IsZero() {
		tcpDur = connDone.Sub(connStart)
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		tlsDur = tlsDone.Sub(tlsStart)
	}
	if !firstByte.IsZero() {
		if !wroteReq.IsZero() && firstByte.After(wroteReq) {
			ttfbDur = firstByte.Sub(wroteReq)
		} else if !tlsDone.IsZero() && firstByte.After(tlsDone) {
			ttfbDur = firstByte.Sub(tlsDone)
		} else if !connDone.IsZero() && firstByte.After(connDone) {
			ttfbDur = firstByte.Sub(connDone)
		}
		if reqEnd.After(firstByte) {
			transferDur = reqEnd.Sub(firstByte)
		}
	}
	totalDur := reqEnd.Sub(reqStart)

	hop := HTTPRedirectHop{
		URL:        targetURL,
		StatusCode: resp.StatusCode,
		Status:     fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode)),
		Location:   strings.TrimSpace(resp.Header.Get("Location")),
		Server:     strings.TrimSpace(resp.Header.Get("Server")),
		Protocol:   resp.Proto,
		TotalMs:    roundMs(totalDur),
	}

	wf := HTTPWaterfallTiming{
		URL:               targetURL,
		Protocol:          resp.Proto,
		StatusCode:        resp.StatusCode,
		DNSMs:             roundMs(dnsDur),
		TCPConnectMs:      roundMs(tcpDur),
		TLSHandshakeMs:    roundMs(tlsDur),
		TTFBMs:            roundMs(ttfbDur),
		ContentTransferMs: roundMs(transferDur),
		TotalMs:           roundMs(totalDur),
	}

	return hop, wf, nil
}

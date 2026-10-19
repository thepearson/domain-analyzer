package analyzer

import (
	"net/http"
	"strings"
	"testing"
)

func TestEvaluateWAF(t *testing.T) {
	tests := []struct {
		name             string
		cnames           []string
		base             *wafProbeResponse
		probe            *wafProbeResponse
		wantDetected     bool
		wantProvider     string
		wantEnforcing    bool
		wantStateSubstr  string
		wantImplSubstr   string
		wantOriginSubstr string
	}{
		{
			name:   "Cloudflare Enforcing with Bot Management",
			cnames: nil,
			base: &wafProbeResponse{
				StatusCode: 200,
				Headers: http.Header{
					"Server":     []string{"cloudflare"},
					"Cf-Ray":     []string{"89abcdef-AKL"},
					"Set-Cookie": []string{"__cf_bm=xyz123; path=/; HttpOnly"},
				},
				Body: "<html>OK</html>",
			},
			probe: &wafProbeResponse{
				StatusCode: 403,
				Headers: http.Header{
					"Server": []string{"cloudflare"},
				},
				Body: "<html>Attention Required! | Cloudflare Ray ID: 89abcdef</html>",
			},
			wantDetected:    true,
			wantProvider:    "Cloudflare",
			wantEnforcing:   true,
			wantStateSubstr: "ENFORCING",
			wantImplSubstr:  "Bot Management: ACTIVE",
		},
		{
			name:   "Cloudflare Passthrough",
			cnames: []string{"example.com.cdn.cloudflare.net"},
			base: &wafProbeResponse{
				StatusCode: 200,
				Headers: http.Header{
					"Server": []string{"cloudflare"},
				},
				Body: "<html>OK</html>",
			},
			probe: &wafProbeResponse{
				StatusCode: 200,
				Headers: http.Header{
					"Server": []string{"cloudflare"},
				},
				Body: "<html>OK</html>",
			},
			wantDetected:    true,
			wantProvider:    "Cloudflare",
			wantEnforcing:   false,
			wantStateSubstr: "PASSTHROUGH / OFF",
			wantImplSubstr:  "Edge Proxy/CDN: ACTIVE",
		},
		{
			name:   "Fastly / Signal Sciences Enforcing (406)",
			cnames: []string{"dualstack.example.map.fastly.net"},
			base: &wafProbeResponse{
				StatusCode: 200,
				Headers: http.Header{
					"X-Served-By": []string{"cache-akl1032-AKL"},
				},
				Body: "<html>Home</html>",
			},
			probe: &wafProbeResponse{
				StatusCode: 406,
				Headers: http.Header{
					"X-Served-By": []string{"cache-akl1032-AKL"},
				},
				Body: "Not Acceptable",
			},
			wantDetected:    true,
			wantProvider:    "Fastly / Next-Gen WAF",
			wantEnforcing:   true,
			wantStateSubstr: "ENFORCING (Blocked - status code 406)",
			wantImplSubstr:  "Fastly Edge/CDN: ACTIVE",
		},
		{
			name:   "AWS WAF Enforcing via x-amzn-errortype",
			cnames: []string{"d111111abcdef8.cloudfront.net"},
			base: &wafProbeResponse{
				StatusCode: 200,
				Headers: http.Header{
					"X-Amz-Cf-Id": []string{"abc123456"},
				},
				Body: "<html>Home</html>",
			},
			probe: &wafProbeResponse{
				StatusCode: 403,
				Headers: http.Header{
					"X-Amzn-Errortype": []string{"WAFForbiddenException"},
				},
				Body: "Forbidden",
			},
			wantDetected:    true,
			wantProvider:    "AWS WAF",
			wantEnforcing:   true,
			wantStateSubstr: "ENFORCING",
			wantImplSubstr:  "Edge/Load Balancer: ACTIVE",
		},
		{
			name:   "Azure Front Door WAF Enforcing",
			cnames: []string{"example.azurefd.net"},
			base: &wafProbeResponse{
				StatusCode: 200,
				Headers: http.Header{
					"X-Azure-Ref": []string{"20261019T000000Z-123456"},
				},
				Body: "<html>Home</html>",
			},
			probe: &wafProbeResponse{
				StatusCode: 403,
				Headers: http.Header{
					"X-Azure-Ref": []string{"20261019T000001Z-123456"},
				},
				Body: "<html>The request is blocked by Front Door</html>",
			},
			wantDetected:    true,
			wantProvider:    "Azure WAF",
			wantEnforcing:   true,
			wantStateSubstr: "ENFORCING",
			wantImplSubstr:  "Front Door / CDN: ACTIVE",
		},
		{
			name:   "RedShield Enforcing",
			cnames: []string{"customer.redshield.net"},
			base: &wafProbeResponse{
				StatusCode: 200,
				Headers: http.Header{
					"X-Redshield-Id": []string{"rs-1"},
				},
				Body: "<html>Home</html>",
			},
			probe: &wafProbeResponse{
				StatusCode: 403,
				Headers:    http.Header{},
				Body:       "<html>Blocked - Request ID: 998877-rs</html>",
			},
			wantDetected:    true,
			wantProvider:    "RedShield",
			wantEnforcing:   true,
			wantStateSubstr: "ENFORCING",
			wantImplSubstr:  "Proxy / In-Flight: ACTIVE",
		},
		{
			name:   "Imperva Enforcing",
			cnames: []string{"xyz.impervadns.net"},
			base: &wafProbeResponse{
				StatusCode: 200,
				Headers: http.Header{
					"X-Cdn": []string{"Imperva"},
				},
				Body: "<html>Home</html>",
			},
			probe: &wafProbeResponse{
				StatusCode: 403,
				Headers: http.Header{
					"X-Iinfo": []string{"12-345678-0NNN"},
				},
				Body: "<html>Request unsuccessful. Incapsula incident ID: 12345</html>",
			},
			wantDetected:    true,
			wantProvider:    "Imperva / Incapsula",
			wantEnforcing:   true,
			wantStateSubstr: "ENFORCING",
			wantImplSubstr:  "Edge Proxy/CDN: ACTIVE",
		},
		{
			name:   "Wordfence Origin Block",
			cnames: nil,
			base: &wafProbeResponse{
				StatusCode: 200,
				Headers:    http.Header{},
				Body:       "<html>WordPress Site</html>",
			},
			probe: &wafProbeResponse{
				StatusCode: 403,
				Headers:    http.Header{},
				Body:       "<html>A potentially unsafe operation has been detected in your request to this site. Generated by Wordfence</html>",
			},
			wantDetected:     true,
			wantOriginSubstr: "Wordfence",
		},
		{
			name:   "No WAF Detected",
			cnames: nil,
			base: &wafProbeResponse{
				StatusCode: 200,
				Headers:    http.Header{"Server": []string{"nginx"}},
				Body:       "<html>Hello World</html>",
			},
			probe: &wafProbeResponse{
				StatusCode: 200,
				Headers:    http.Header{"Server": []string{"nginx"}},
				Body:       "<html>Hello World</html>",
			},
			wantDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateWAF(tt.cnames, tt.base, tt.probe)
			if got.Detected != tt.wantDetected {
				t.Fatalf("EvaluateWAF().Detected = %v, want %v (Summary: %s)", got.Detected, tt.wantDetected, got.Summary)
			}

			if tt.wantProvider != "" {
				found := false
				for _, p := range got.Providers {
					if p.Provider == tt.wantProvider {
						found = true
						if p.Enforcing != tt.wantEnforcing {
							t.Errorf("Provider %s Enforcing = %v, want %v", p.Provider, p.Enforcing, tt.wantEnforcing)
						}
						if tt.wantStateSubstr != "" && !strings.Contains(p.State, tt.wantStateSubstr) {
							t.Errorf("Provider %s State = %q, want substring %q", p.Provider, p.State, tt.wantStateSubstr)
						}
						implJoined := strings.Join(p.Implementation, "; ")
						if tt.wantImplSubstr != "" && !strings.Contains(implJoined, tt.wantImplSubstr) {
							t.Errorf("Provider %s Implementation = %q, want substring %q", p.Provider, implJoined, tt.wantImplSubstr)
						}
					}
				}
				if !found {
					t.Errorf("Expected provider %q not found in %+v", tt.wantProvider, got.Providers)
				}
			}

			if tt.wantOriginSubstr != "" {
				notesJoined := strings.Join(got.OriginNotes, "; ")
				if !strings.Contains(notesJoined, tt.wantOriginSubstr) {
					t.Errorf("OriginNotes = %q, want substring %q", notesJoined, tt.wantOriginSubstr)
				}
			}
		})
	}
}

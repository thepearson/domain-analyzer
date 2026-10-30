package analyzer

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

type DKIMSelectorInfo struct {
	Selector  string `json:"selector"`
	KeyType   string `json:"key_type,omitempty"`
	CNAME     string `json:"cname,omitempty"`
	RawRecord string `json:"raw_record,omitempty"`
}

type MTASTSDetails struct {
	Found      bool     `json:"found"`
	DNSRecord  string   `json:"dns_record,omitempty"`
	ID         string   `json:"id,omitempty"`
	PolicyURL  string   `json:"policy_url,omitempty"`
	Mode       string   `json:"mode,omitempty"` // "enforce", "testing", "none"
	MaxAge     string   `json:"max_age,omitempty"`
	MXPatterns []string `json:"mx_patterns,omitempty"`
}

type TLSRPTDetails struct {
	Found     bool     `json:"found"`
	RawRecord string   `json:"raw_record,omitempty"`
	Endpoints []string `json:"endpoints,omitempty"`
}

type BIMIDetails struct {
	Found        bool   `json:"found"`
	RawRecord    string `json:"raw_record,omitempty"`
	LogoURL      string `json:"logo_url,omitempty"`
	AuthorityURL string `json:"authority_url,omitempty"`
}

var commonDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2",
	"s1", "s2", "mandrill", "mailgun", "smtp", "dkim",
	"protonmail", "protonmail2", "protonmail3", "zoho",
	"fastmail", "fm1", "fm2", "fm3", "everlytickey1", "cm",
}

// InspectEmailDeliverability performs a deep-dive email authentication and deliverability check
// on a domain/apex domain, covering MX hosts, SPF, DMARC, DKIM selectors, MTA-STS, TLS-RPT, and BIMI.
func InspectEmailDeliverability(domain string) EmailInfo {
	clean := CleanDomainTarget(NormalizeTarget(domain))
	apex, err := publicsuffix.EffectiveTLDPlusOne(clean)
	if err != nil || apex == "" {
		apex = clean
	}

	var (
		email EmailInfo
		mu    sync.Mutex
		wg    sync.WaitGroup
	)
	wg.Add(6)

	// 1. MX Records & Mail Providers
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		mxs, err := net.DefaultResolver.LookupMX(ctx, apex)
		if err != nil || len(mxs) == 0 {
			return
		}
		sort.Slice(mxs, func(i, j int) bool {
			if mxs[i].Pref != mxs[j].Pref {
				return mxs[i].Pref < mxs[j].Pref
			}
			return mxs[i].Host < mxs[j].Host
		})
		var hosts []string
		seen := make(map[string]bool)
		for _, mx := range mxs {
			h := strings.TrimSuffix(strings.TrimSpace(mx.Host), ".")
			lower := strings.ToLower(h)
			if h != "" && !seen[lower] {
				seen[lower] = true
				hosts = append(hosts, h)
			}
		}
		providers := IdentifyMailProviders(hosts)
		mu.Lock()
		email.MXRecords = hosts
		email.MailProviders = providers
		mu.Unlock()
	}()

	// 2. SPF & DMARC
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if txts, err := net.DefaultResolver.LookupTXT(ctx, apex); err == nil {
			for _, txt := range txts {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
					spf := ParseSPF(txt)
					mu.Lock()
					email.SPFRecord = spf
					mu.Unlock()
					break
				}
			}
		}
		if dmarcTxts, err := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+apex); err == nil {
			for _, txt := range dmarcTxts {
				if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(txt)), "V=DMARC1") {
					dmarc := ParseDMARC(txt)
					mu.Lock()
					email.DMARCRecord = dmarc
					mu.Unlock()
					break
				}
			}
		}
	}()

	// 3. Common DKIM Selectors Enumeration
	go func() {
		defer wg.Done()
		dkims := probeDKIMSelectors(apex)
		mu.Lock()
		email.DKIMRecords = dkims
		mu.Unlock()
	}()

	// 4. MTA-STS (RFC 8461: _mta-sts.<apex> + https://mta-sts.<apex>/.well-known/mta-sts.txt)
	go func() {
		defer wg.Done()
		mtasts := lookupMTASTS(apex)
		if mtasts != nil && mtasts.Found {
			mu.Lock()
			email.MTASTS = mtasts
			mu.Unlock()
		}
	}()

	// 5. SMTP TLS-RPT (RFC 8460: _smtp._tls.<apex>)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		txts, err := net.DefaultResolver.LookupTXT(ctx, "_smtp._tls."+apex)
		if err != nil {
			return
		}
		for _, txt := range txts {
			if parsed := ParseTLSRPT(txt); parsed.Found {
				mu.Lock()
				email.TLSRPT = &parsed
				mu.Unlock()
				break
			}
		}
	}()

	// 6. BIMI (Brand Indicators for Message Identification: default._bimi.<apex>)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		txts, err := net.DefaultResolver.LookupTXT(ctx, "default._bimi."+apex)
		if err != nil {
			return
		}
		for _, txt := range txts {
			if parsed := ParseBIMI(txt); parsed.Found {
				mu.Lock()
				email.BIMI = &parsed
				mu.Unlock()
				break
			}
		}
	}()

	wg.Wait()
	email.DeepChecked = true
	return email
}

func probeDKIMSelectors(apexDomain string) []DKIMSelectorInfo {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []DKIMSelectorInfo
		sem     = make(chan struct{}, 10)
	)

	for _, sel := range commonDKIMSelectors {
		wg.Add(1)
		go func(selector string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			qname := selector + "._domainkey." + apexDomain
			ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
			defer cancel()

			var cnameTarget string
			if cn, err := net.DefaultResolver.LookupCNAME(ctx, qname); err == nil {
				cleanCN := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cn)), ".")
				if cleanCN != "" && cleanCN != strings.ToLower(qname) {
					cnameTarget = cleanCN
				}
			}

			txts, err := net.DefaultResolver.LookupTXT(ctx, qname)
			if err == nil && len(txts) > 0 {
				combined := strings.Join(txts, "")
				if info, ok := ParseDKIMRecord(selector, combined, cnameTarget); ok {
					mu.Lock()
					results = append(results, info)
					mu.Unlock()
					return
				}
			}
		}(sel)
	}

	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		return results[i].Selector < results[j].Selector
	})
	return results
}

// ParseDKIMRecord parses a raw DKIM TXT record for a given selector and returns true if it contains a valid public key.
func ParseDKIMRecord(selector, raw, cname string) (DKIMSelectorInfo, bool) {
	trimmed := strings.TrimSpace(raw)
	lower := strings.ToLower(trimmed)
	if !strings.Contains(lower, "p=") && !strings.Contains(lower, "v=dkim1") {
		return DKIMSelectorInfo{}, false
	}

	keyType := "rsa"
	hasNonEmptyKey := false
	for _, part := range strings.Split(trimmed, ";") {
		kv := strings.TrimSpace(part)
		lowerKV := strings.ToLower(kv)
		if strings.HasPrefix(lowerKV, "k=") {
			val := strings.TrimSpace(kv[2:])
			if val != "" {
				keyType = val
			}
		} else if strings.HasPrefix(lowerKV, "p=") {
			pubKey := strings.TrimSpace(kv[2:])
			if pubKey != "" {
				hasNonEmptyKey = true
			}
		}
	}

	// Ignore explicitly revoked DKIM keys (empty p=)
	if !hasNonEmptyKey {
		return DKIMSelectorInfo{}, false
	}

	displayRaw := trimmed
	if len(displayRaw) > 140 {
		displayRaw = displayRaw[:137] + "..."
	}

	return DKIMSelectorInfo{
		Selector:  selector,
		KeyType:   keyType,
		CNAME:     cname,
		RawRecord: displayRaw,
	}, true
}

func lookupMTASTS(apexDomain string) *MTASTSDetails {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	var details MTASTSDetails
	if txts, err := net.DefaultResolver.LookupTXT(ctx, "_mta-sts."+apexDomain); err == nil {
		for _, txt := range txts {
			if parsed := ParseMTASTSDNS(txt); parsed.Found {
				details = parsed
				break
			}
		}
	}

	policyURL := "https://mta-sts." + apexDomain + "/.well-known/mta-sts.txt"
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, err := http.NewRequest("GET", policyURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", wafUserAgent)
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				if !looksLikeHTMLPage(body) {
					ParseMTASTSPolicy(string(body), &details)
					if details.Mode != "" {
						details.Found = true
						details.PolicyURL = policyURL
					}
				}
			}
		}
	}

	return &details
}

// ParseMTASTSDNS parses a `_mta-sts.<domain>` TXT record (`v=STSv1; id=...`).
func ParseMTASTSDNS(raw string) MTASTSDetails {
	var d MTASTSDetails
	trimmed := strings.TrimSpace(raw)
	if !strings.Contains(strings.ToUpper(trimmed), "V=STSV1") {
		return d
	}
	d.Found = true
	d.DNSRecord = trimmed
	for _, part := range strings.Split(trimmed, ";") {
		kv := strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(kv), "id=") {
			d.ID = strings.TrimSpace(kv[3:])
		}
	}
	return d
}

// ParseMTASTSPolicy parses the text body of `/.well-known/mta-sts.txt`.
func ParseMTASTSPolicy(raw string, details *MTASTSDetails) {
	if details == nil {
		return
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		v := strings.TrimSpace(parts[1])
		switch k {
		case "mode":
			details.Mode = v
		case "max_age":
			details.MaxAge = v
		case "mx":
			if v != "" {
				details.MXPatterns = append(details.MXPatterns, v)
			}
		}
	}
}

// ParseTLSRPT parses a `_smtp._tls.<domain>` TXT record (`v=TLSRPTv1; rua=...`).
func ParseTLSRPT(raw string) TLSRPTDetails {
	var d TLSRPTDetails
	trimmed := strings.TrimSpace(raw)
	if !strings.Contains(strings.ToUpper(trimmed), "V=TLSRPTV1") {
		return d
	}
	d.Found = true
	d.RawRecord = trimmed
	for _, part := range strings.Split(trimmed, ";") {
		kv := strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(kv), "rua=") {
			for _, ep := range strings.Split(kv[4:], ",") {
				ep = strings.TrimSpace(ep)
				if ep != "" {
					d.Endpoints = append(d.Endpoints, ep)
				}
			}
		}
	}
	return d
}

// ParseBIMI parses a `default._bimi.<domain>` TXT record (`v=BIMI1; l=...; a=...`).
func ParseBIMI(raw string) BIMIDetails {
	var d BIMIDetails
	trimmed := strings.TrimSpace(raw)
	if !strings.Contains(strings.ToUpper(trimmed), "V=BIMI1") {
		return d
	}
	d.Found = true
	d.RawRecord = trimmed
	for _, part := range strings.Split(trimmed, ";") {
		kv := strings.TrimSpace(part)
		lowerKV := strings.ToLower(kv)
		if strings.HasPrefix(lowerKV, "l=") {
			d.LogoURL = strings.TrimSpace(kv[2:])
		} else if strings.HasPrefix(lowerKV, "a=") {
			d.AuthorityURL = strings.TrimSpace(kv[2:])
		}
	}
	return d
}

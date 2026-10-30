package analyzer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

var oidCertTransparencySCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

func getTLSInfo(domain string, info *DomainInfo) error {
	tlsInfo, err := InspectTLS(domain)
	if err != nil {
		return err
	}
	info.Lock()
	info.TLS = tlsInfo
	info.Unlock()
	return nil
}

// InspectTLS performs a deep TLS handshake, protocol version enumeration, cipher suite analysis,
// certificate chain validation, OCSP/CT check, and calculates a security grade (A+ to F).
func InspectTLS(target string) (TLSInfo, error) {
	clean := NormalizeTarget(target)
	if clean == "" {
		return TLSInfo{}, fmt.Errorf("empty target")
	}
	isIP := IsIPAddress(clean)

	conf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	if !isIP {
		conf.ServerName = clean
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(clean, "443"), conf)
	if err != nil {
		return TLSInfo{}, err
	}
	state := conn.ConnectionState()
	_ = conn.Close()

	var t TLSInfo
	t.HasTLS = true
	t.NegotiatedVersion = tlsVersionString(state.Version)
	t.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	t.ALPNProtocol = state.NegotiatedProtocol
	t.OCSPStapled = len(state.OCSPResponse) > 0
	if len(state.SignedCertificateTimestamps) > 0 {
		t.HasCertTransparency = true
	}

	certs := state.PeerCertificates
	t.ChainLength = len(certs)
	if len(certs) > 0 {
		leaf := certs[0]
		t.SubjectCN = leaf.Subject.CommonName
		if len(leaf.Issuer.Organization) > 0 {
			t.TLSIssuer = leaf.Issuer.Organization[0]
		} else {
			t.TLSIssuer = leaf.Issuer.CommonName
		}
		t.ValidFrom = leaf.NotBefore.UTC().Format(time.RFC3339)
		t.TLSExpiry = leaf.NotAfter.UTC().Format(time.RFC3339)
		t.DaysRemaining = int(math.Floor(time.Until(leaf.NotAfter).Hours() / 24.0))
		t.KeyAlgorithm = describePublicKey(leaf)
		t.SignatureAlgorithm = leaf.SignatureAlgorithm.String()
		if leaf.SerialNumber != nil {
			t.SerialNumber = strings.ToUpper(leaf.SerialNumber.Text(16))
		}
		if hasSCTExtension(leaf) {
			t.HasCertTransparency = true
		}

		// Collect unique SANs (plus Subject CN if domain-like)
		var sans []string
		seenSAN := make(map[string]bool)
		addSAN := func(name string) {
			name = strings.TrimSpace(name)
			lower := strings.ToLower(name)
			if name != "" && !seenSAN[lower] {
				seenSAN[lower] = true
				sans = append(sans, name)
			}
		}
		for _, dnsName := range leaf.DNSNames {
			addSAN(dnsName)
		}
		if isIP && leaf.Subject.CommonName != "" && strings.Contains(leaf.Subject.CommonName, ".") && !IsIPAddress(leaf.Subject.CommonName) {
			addSAN(leaf.Subject.CommonName)
		}
		t.SANDomains = sans

		// Summarize peer certificate chain
		for i, c := range certs {
			role := "Intermediate"
			if i == 0 {
				role = "Leaf"
			} else if c.IsCA && c.CheckSignatureFrom(c) == nil {
				role = "Root"
			}
			name := c.Subject.CommonName
			if name == "" && len(c.Subject.Organization) > 0 {
				name = c.Subject.Organization[0]
			}
			t.ChainSummary = append(t.ChainSummary, fmt.Sprintf("#%d %s: %s (%s)", i+1, role, name, describePublicKey(c)))
		}

		// Verify certificate chain against system root CAs
		valid, verifyErr := verifyCertificateChain(certs, clean, isIP)
		t.ChainValid = valid
		if verifyErr != nil {
			t.ChainError = verifyErr.Error()
		}
	}

	// Concurrently probe supported TLS protocol versions (TLS 1.0, 1.1, 1.2, 1.3)
	supported, deprecated := probeSupportedTLSVersions(clean, isIP)
	if len(supported) == 0 && t.NegotiatedVersion != "" {
		supported = []string{t.NegotiatedVersion}
	}
	t.SupportedVersions = supported
	t.DeprecatedVersions = deprecated

	EvaluateTLSGrade(&t, isIP)
	return t, nil
}

func probeSupportedTLSVersions(host string, isIP bool) (supported []string, deprecated []string) {
	versions := []struct {
		id         uint16
		name       string
		deprecated bool
	}{
		{tls.VersionTLS10, "TLS 1.0", true},
		{tls.VersionTLS11, "TLS 1.1", true},
		{tls.VersionTLS12, "TLS 1.2", false},
		{tls.VersionTLS13, "TLS 1.3", false},
	}

	results := make([]bool, len(versions))
	var wg sync.WaitGroup
	for i, v := range versions {
		wg.Add(1)
		go func(idx int, ver uint16) {
			defer wg.Done()
			cfg := &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         ver,
				MaxVersion:         ver,
			}
			if !isIP {
				cfg.ServerName = host
			}
			d := &net.Dialer{Timeout: 3500 * time.Millisecond}
			c, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, "443"), cfg)
			if err == nil {
				_ = c.Close()
				results[idx] = true
			}
		}(i, v.id)
	}
	wg.Wait()

	for i, v := range versions {
		if results[i] {
			supported = append(supported, v.name)
			if v.deprecated {
				deprecated = append(deprecated, v.name)
			}
		}
	}
	return supported, deprecated
}

func verifyCertificateChain(certs []*x509.Certificate, host string, isIP bool) (bool, error) {
	if len(certs) == 0 {
		return false, fmt.Errorf("no peer certificates presented")
	}
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}
	if !isIP {
		opts.DNSName = host
	}
	_, err := certs[0].Verify(opts)
	if err != nil {
		return false, err
	}
	return true, nil
}

func describePublicKey(cert *x509.Certificate) string {
	if cert == nil || cert.PublicKey == nil {
		return "Unknown"
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", pub.N.BitLen())
	case *ecdsa.PublicKey:
		if pub.Curve != nil && pub.Curve.Params() != nil {
			return fmt.Sprintf("ECDSA %s (%d-bit)", pub.Curve.Params().Name, pub.Curve.Params().BitSize)
		}
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519 (256-bit)"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

func hasSCTExtension(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidCertTransparencySCT) {
			return true
		}
	}
	return false
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// EvaluateTLSGrade computes a security grade (A+, A, B, C, F) and actionable warnings for a TLSInfo struct.
func EvaluateTLSGrade(t *TLSInfo, isIP bool) {
	if t == nil || !t.HasTLS {
		return
	}

	var warnings []string
	score := 100

	// 1. Certificate expiration & trust chain
	if t.DaysRemaining < 0 {
		score = 0
		warnings = append(warnings, fmt.Sprintf("Certificate expired %d days ago", -t.DaysRemaining))
	} else if t.DaysRemaining < 14 {
		score -= 15
		warnings = append(warnings, fmt.Sprintf("Certificate expires soon (%d days remaining)", t.DaysRemaining))
	} else if t.DaysRemaining < 30 {
		warnings = append(warnings, fmt.Sprintf("Certificate expires in %d days", t.DaysRemaining))
	}

	if !t.ChainValid {
		if !isIP {
			score = 0
			if t.ChainError != "" {
				warnings = append(warnings, "Untrusted or mismatched certificate chain: "+t.ChainError)
			} else {
				warnings = append(warnings, "Certificate chain failed validation")
			}
		} else {
			score -= 15
			warnings = append(warnings, "Direct IP connection does not match certificate hostname")
		}
	}

	// 2. Deprecated TLS protocol versions (TLS 1.0 / 1.1)
	if len(t.DeprecatedVersions) > 0 {
		if score > 75 {
			score = 75 // Cap at B
		}
		warnings = append(warnings, "Supports deprecated protocol(s): "+strings.Join(t.DeprecatedVersions, ", "))
	}

	// 3. Modern TLS 1.3 support
	supportsTLS13 := t.NegotiatedVersion == "TLS 1.3"
	for _, v := range t.SupportedVersions {
		if v == "TLS 1.3" {
			supportsTLS13 = true
			break
		}
	}
	if !supportsTLS13 && score > 88 {
		score = 88 // Cap at A (not A+) if TLS 1.3 is not supported
		warnings = append(warnings, "TLS 1.3 is not supported (max protocol is "+t.NegotiatedVersion+")")
	}

	// 4. Cipher suite & key strength checks
	cipherUpper := strings.ToUpper(t.CipherSuite)
	if strings.Contains(cipherUpper, "RC4") || strings.Contains(cipherUpper, "3DES") || strings.Contains(cipherUpper, "NULL") {
		score = 0
		warnings = append(warnings, "Insecure cipher suite negotiated: "+t.CipherSuite)
	} else if strings.Contains(cipherUpper, "CBC") {
		if score > 78 {
			score = 78
		}
		warnings = append(warnings, "CBC-mode cipher negotiated instead of modern AEAD (GCM/ChaCha20)")
	}

	if strings.HasPrefix(t.KeyAlgorithm, "RSA 1024") {
		if score > 65 {
			score = 65
		}
		warnings = append(warnings, "Weak 1024-bit RSA public key")
	}

	t.GradeWarnings = warnings

	switch {
	case score == 0:
		t.Grade = "F"
		t.GradeSummary = "Critical TLS configuration or certificate trust failure"
	case score < 70:
		t.Grade = "C"
		t.GradeSummary = "Weak TLS configuration requiring remediation"
	case score < 85:
		t.Grade = "B"
		t.GradeSummary = "Acceptable TLS, but supports legacy protocols or ciphers"
	case score >= 95 && supportsTLS13 && (t.HasCertTransparency || t.OCSPStapled):
		t.Grade = "A+"
		t.GradeSummary = "Exceptional TLS 1.3 configuration with strong AEAD cipher & Certificate Transparency"
	default:
		t.Grade = "A"
		t.GradeSummary = "Strong modern TLS configuration and valid certificate chain"
	}
}

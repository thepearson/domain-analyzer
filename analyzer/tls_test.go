package analyzer

import (
	"testing"
)

func TestEvaluateTLSGrade(t *testing.T) {
	t.Run("A+ Modern TLS 1.3 with CT", func(t *testing.T) {
		info := TLSInfo{
			HasTLS:              true,
			NegotiatedVersion:   "TLS 1.3",
			SupportedVersions:   []string{"TLS 1.2", "TLS 1.3"},
			CipherSuite:         "TLS_AES_128_GCM_SHA256",
			KeyAlgorithm:        "ECDSA P-256 (256-bit)",
			ChainValid:          true,
			DaysRemaining:       75,
			HasCertTransparency: true,
		}
		EvaluateTLSGrade(&info, false)
		if info.Grade != "A+" {
			t.Errorf("expected Grade A+, got %s (warnings: %v)", info.Grade, info.GradeWarnings)
		}
	})

	t.Run("B when deprecated TLS 1.0/1.1 supported", func(t *testing.T) {
		info := TLSInfo{
			HasTLS:             true,
			NegotiatedVersion:  "TLS 1.3",
			SupportedVersions:  []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"},
			DeprecatedVersions: []string{"TLS 1.0", "TLS 1.1"},
			CipherSuite:        "TLS_AES_128_GCM_SHA256",
			KeyAlgorithm:       "RSA 2048-bit",
			ChainValid:         true,
			DaysRemaining:      60,
		}
		EvaluateTLSGrade(&info, false)
		if info.Grade != "B" {
			t.Errorf("expected Grade B when deprecated TLS 1.0/1.1 enabled, got %s", info.Grade)
		}
	})

	t.Run("F when certificate expired or chain invalid", func(t *testing.T) {
		info := TLSInfo{
			HasTLS:            true,
			NegotiatedVersion: "TLS 1.3",
			SupportedVersions: []string{"TLS 1.3"},
			CipherSuite:       "TLS_AES_128_GCM_SHA256",
			ChainValid:        false,
			ChainError:        "x509: certificate signed by unknown authority",
			DaysRemaining:     -5,
		}
		EvaluateTLSGrade(&info, false)
		if info.Grade != "F" {
			t.Errorf("expected Grade F for expired/untrusted cert, got %s", info.Grade)
		}
	})
}

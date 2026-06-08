package analyzer

import (
	"crypto/tls"
	"net"
	"time"
)

func getTLSInfo(domain string, info *DomainInfo) error {
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", conf)
	if err != nil {
		return err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		info.Lock()
		defer info.Unlock()

		info.TLS.HasTLS = true
		if len(certs[0].Issuer.Organization) > 0 {
			info.TLS.TLSIssuer = certs[0].Issuer.Organization[0]
		} else {
			info.TLS.TLSIssuer = certs[0].Issuer.CommonName
		}
		info.TLS.TLSExpiry = certs[0].NotAfter.Format(time.RFC3339)
		info.TLS.SANDomains = certs[0].DNSNames
	}

	return nil
}

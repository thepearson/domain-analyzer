package analyzer

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type PortService struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	State   string `json:"state"` // "open"
	Banner  string `json:"banner,omitempty"`
}

var commonPorts = []struct {
	Port    int
	Service string
}{
	{21, "FTP"},
	{22, "SSH"},
	{23, "Telnet"},
	{25, "SMTP"},
	{53, "DNS"},
	{80, "HTTP"},
	{110, "POP3"},
	{143, "IMAP"},
	{443, "HTTPS"},
	{465, "SMTPS"},
	{587, "SMTP Submission"},
	{993, "IMAPS"},
	{995, "POP3S"},
	{1433, "MSSQL"},
	{3306, "MySQL"},
	{3389, "RDP"},
	{5432, "PostgreSQL"},
	{6379, "Redis"},
	{8080, "HTTP-Alt"},
	{8443, "HTTPS-Alt"},
	{27017, "MongoDB"},
}

// ScanPorts probes common TCP ports on an IP address concurrently and grabs service banners where available.
func ScanPorts(ip string) []PortService {
	cleanIP := NormalizeTarget(ip)
	if cleanIP == "" {
		return nil
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []PortService
	)

	for _, p := range commonPorts {
		wg.Add(1)
		go func(port int, defaultService string) {
			defer wg.Done()
			addr := net.JoinHostPort(cleanIP, fmt.Sprintf("%d", port))
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			banner := grabBanner(conn, cleanIP, port)
			mu.Lock()
			results = append(results, PortService{
				Port:    port,
				Service: defaultService,
				State:   "open",
				Banner:  banner,
			})
			mu.Unlock()
		}(p.Port, p.Service)
	}

	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	return results
}

func grabBanner(conn net.Conn, host string, port int) string {
	_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))

	// For HTTP ports, send a minimal HEAD request to elicit a Server header
	if port == 80 || port == 8080 {
		_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", host, wafUserAgent)
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return ""
	}
	raw := string(buf[:n])

	// If HTTP response, extract status line and Server header
	if strings.HasPrefix(raw, "HTTP/") {
		lines := strings.Split(raw, "\r\n")
		statusLine := strings.TrimSpace(lines[0])
		serverHdr := ""
		for _, l := range lines[1:] {
			if strings.HasPrefix(strings.ToLower(l), "server:") {
				serverHdr = strings.TrimSpace(l)
				break
			}
		}
		if serverHdr != "" {
			return statusLine + " (" + serverHdr + ")"
		}
		return statusLine
	}

	// Clean non-printable characters from banner
	var cleaned strings.Builder
	for _, r := range raw {
		if r == '\r' || r == '\n' {
			if cleaned.Len() > 0 {
				break
			}
			continue
		}
		if r >= 32 && r <= 126 {
			cleaned.WriteRune(r)
		}
	}
	res := strings.TrimSpace(cleaned.String())
	if len(res) > 100 {
		res = res[:97] + "..."
	}
	return res
}


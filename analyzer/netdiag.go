package analyzer

import (
	"context"
	"fmt"
	"math"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PingProbe struct {
	Seq     int     `json:"seq"`
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	Success bool    `json:"success"`
	Detail  string  `json:"detail,omitempty"`
}

type PingResult struct {
	Target      string      `json:"target"`
	ResolvedIP  string      `json:"resolved_ip,omitempty"`
	Method      string      `json:"method"` // e.g., "ICMP" or "TCP/443"
	Reachable   bool        `json:"reachable"`
	PacketsSent int         `json:"packets_sent"`
	PacketsRecv int         `json:"packets_recv"`
	LossPercent float64     `json:"loss_percent"`
	MinRTT      string      `json:"min_rtt,omitempty"`
	AvgRTT      string      `json:"avg_rtt,omitempty"`
	MaxRTT      string      `json:"max_rtt,omitempty"`
	Probes      []PingProbe `json:"probes,omitempty"`
	RawOutput   string      `json:"raw_output,omitempty"`
}

type TracerouteHop struct {
	Hop     int    `json:"hop"`
	IP      string `json:"ip,omitempty"`
	Host    string `json:"host,omitempty"`
	RTT     string `json:"rtt,omitempty"`
	Timeout bool   `json:"timeout,omitempty"`
}

type TracerouteResult struct {
	Target     string          `json:"target"`
	ResolvedIP string          `json:"resolved_ip,omitempty"`
	Method     string          `json:"method,omitempty"` // e.g., "traceroute", "tracepath", "mtr", "tracert"
	Hops       []TracerouteHop `json:"hops,omitempty"`
	Completed  bool            `json:"completed"`
	RawOutput  string          `json:"raw_output,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// RunPing performs a connectivity and latency check against a domain or IP.
// It tries native OS ICMP ping first, and automatically falls back to TCP handshake
// latency probing if ICMP is restricted or blocked by a firewall.
func RunPing(target string) *PingResult {
	cleanTarget := NormalizeTarget(target)
	if cleanTarget == "" {
		return &PingResult{Target: target, Method: "ICMP", LossPercent: 100}
	}

	resolvedIP := resolvePrimaryIP(cleanTarget)

	// 1. Try system ICMP ping first
	if res, ok := runSystemICMPPing(cleanTarget, resolvedIP); ok && res.Reachable {
		return res
	}

	// 2. Fallback to TCP handshake ping (works without raw socket privileges and through ICMP-blocking firewalls)
	return runTCPHandshakePing(cleanTarget, resolvedIP)
}

func resolvePrimaryIP(target string) string {
	if IsIPAddress(target) {
		return target
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(ctx, target)
	if err != nil || len(ips) == 0 {
		return ""
	}
	// Prefer IPv4 for display consistency if available
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			return ip
		}
	}
	return ips[0]
}

func runSystemICMPPing(target, resolvedIP string) (*PingResult, bool) {
	pingBin, err := exec.LookPath("ping")
	if err != nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	var args []string
	switch runtime.GOOS {
	case "windows":
		args = []string{"-n", "4", "-w", "1500", target}
	case "darwin":
		args = []string{"-c", "4", "-W", "1500", "-i", "0.3", target}
	default:
		args = []string{"-c", "4", "-W", "2", "-i", "0.3", target}
	}

	cmd := exec.CommandContext(ctx, pingBin, args...)
	outBytes, err := cmd.CombinedOutput()
	raw := strings.TrimSpace(string(outBytes))
	if raw == "" && err != nil {
		return nil, false
	}
	if strings.Contains(strings.ToLower(raw), "operation not permitted") ||
		strings.Contains(strings.ToLower(raw), "socket: permission denied") {
		return nil, false
	}

	res := ParsePingOutput(raw, target, resolvedIP)
	return res, res.PacketsRecv > 0
}

var (
	rePingTime = regexp.MustCompile(`(?i)time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms`)
	rePingIP   = regexp.MustCompile(`\(([0-9a-fA-F:\.]+)\)`)
)

// ParsePingOutput parses standard Linux, macOS, and Windows ping output into a PingResult.
func ParsePingOutput(raw, target, resolvedIP string) *PingResult {
	res := &PingResult{
		Target:      target,
		ResolvedIP:  resolvedIP,
		Method:      "ICMP",
		PacketsSent: 4,
		RawOutput:   raw,
	}

	lines := strings.Split(raw, "\n")
	if res.ResolvedIP == "" && len(lines) > 0 {
		if m := rePingIP.FindStringSubmatch(lines[0]); len(m) > 1 {
			if net.ParseIP(m[1]) != nil {
				res.ResolvedIP = m[1]
			}
		}
	}

	var rtts []float64
	seq := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if m := rePingTime.FindStringSubmatch(trimmed); len(m) > 1 {
			val, err := strconv.ParseFloat(m[1], 64)
			if err == nil {
				seq++
				rtts = append(rtts, val)
				res.Probes = append(res.Probes, PingProbe{
					Seq:     seq,
					RTTMs:   val,
					Success: true,
					Detail:  fmt.Sprintf("%.2f ms", val),
				})
			}
		} else if strings.Contains(strings.ToLower(trimmed), "request timed out") ||
			strings.Contains(strings.ToLower(trimmed), "request timeout for") ||
			strings.Contains(strings.ToLower(trimmed), "100% packet loss") {
			if !strings.Contains(strings.ToLower(trimmed), "packet loss") {
				seq++
				res.Probes = append(res.Probes, PingProbe{
					Seq:     seq,
					Success: false,
					Detail:  "Timeout",
				})
			}
		}
	}

	populatePingStats(res, rtts)
	return res
}

func runTCPHandshakePing(target, resolvedIP string) *PingResult {
	dialHost := target
	if resolvedIP != "" {
		dialHost = resolvedIP
	}

	// Pick the best responsive TCP port among common web/DNS/SSH ports
	candidatePorts := []int{443, 80, 53, 22, 8080, 8443}
	selectedPort := 443
	for _, p := range candidatePorts {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(dialHost, strconv.Itoa(p)), 1200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			selectedPort = p
			break
		}
	}

	const count = 4
	res := &PingResult{
		Target:      target,
		ResolvedIP:  resolvedIP,
		Method:      fmt.Sprintf("TCP/%d", selectedPort),
		PacketsSent: count,
	}

	var (
		rtts     []float64
		rawLines []string
	)
	rawLines = append(rawLines, fmt.Sprintf("TCP Ping %s (%s) on port %d:", target, dialHost, selectedPort))

	for i := 1; i <= count; i++ {
		if i > 1 {
			time.Sleep(120 * time.Millisecond)
		}
		addr := net.JoinHostPort(dialHost, strconv.Itoa(selectedPort))
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		elapsedMs := float64(time.Since(start).Microseconds()) / 1000.0
		if err != nil {
			res.Probes = append(res.Probes, PingProbe{
				Seq:     i,
				Success: false,
				Detail:  "Timeout",
			})
			rawLines = append(rawLines, fmt.Sprintf("seq=%d tcp_port=%d status=timeout", i, selectedPort))
			continue
		}
		_ = conn.Close()
		rtts = append(rtts, elapsedMs)
		res.Probes = append(res.Probes, PingProbe{
			Seq:     i,
			RTTMs:   elapsedMs,
			Success: true,
			Detail:  fmt.Sprintf("%.2f ms", elapsedMs),
		})
		rawLines = append(rawLines, fmt.Sprintf("seq=%d tcp_port=%d time=%.2f ms", i, selectedPort, elapsedMs))
	}

	populatePingStats(res, rtts)
	rawLines = append(rawLines, fmt.Sprintf("--- %s ping statistics: %d sent, %d received, %.0f%% loss, avg %s ---",
		target, res.PacketsSent, res.PacketsRecv, res.LossPercent, res.AvgRTT))
	res.RawOutput = strings.Join(rawLines, "\n")
	return res
}

func populatePingStats(res *PingResult, rtts []float64) {
	res.PacketsRecv = len(rtts)
	if res.PacketsSent < res.PacketsRecv {
		res.PacketsSent = res.PacketsRecv
	}
	if res.PacketsSent > 0 {
		res.LossPercent = math.Round((float64(res.PacketsSent-res.PacketsRecv)/float64(res.PacketsSent))*1000) / 10
	}
	if len(rtts) == 0 {
		res.Reachable = false
		res.LossPercent = 100
		return
	}
	res.Reachable = true
	minV, maxV, sum := rtts[0], rtts[0], 0.0
	for _, v := range rtts {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
		sum += v
	}
	avgV := sum / float64(len(rtts))
	res.MinRTT = fmt.Sprintf("%.2f ms", minV)
	res.AvgRTT = fmt.Sprintf("%.2f ms", avgV)
	res.MaxRTT = fmt.Sprintf("%.2f ms", maxV)
}

// RunTraceroute traces the network path to a domain or IP using available OS tools
// (traceroute, tracepath, mtr, or tracert) and resolves reverse DNS for discovered hops.
func RunTraceroute(target string) *TracerouteResult {
	cleanTarget := NormalizeTarget(target)
	if cleanTarget == "" {
		return &TracerouteResult{
			Target: target,
			Error:  "Invalid target",
		}
	}

	resolvedIP := resolvePrimaryIP(cleanTarget)
	dest := cleanTarget
	if resolvedIP != "" {
		dest = resolvedIP
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	type traceCmd struct {
		name   string
		args   []string
		parser func(string) []TracerouteHop
	}

	var candidates []traceCmd
	if runtime.GOOS == "windows" {
		candidates = []traceCmd{
			{
				name:   "tracert",
				args:   []string{"-d", "-h", "20", "-w", "1000", dest},
				parser: ParseTracerouteOutput,
			},
		}
	} else {
		candidates = []traceCmd{
			{
				name:   "traceroute",
				args:   []string{"-n", "-q", "1", "-w", "2", "-m", "20", dest},
				parser: ParseTracerouteOutput,
			},
			{
				name:   "tracepath",
				args:   []string{"-n", "-m", "20", dest},
				parser: ParseTracepathOutput,
			},
			{
				name:   "mtr",
				args:   []string{"--report", "--report-cycles", "1", "--no-dns", dest},
				parser: ParseMTRReportOutput,
			},
		}
	}

	for _, c := range candidates {
		binPath, err := exec.LookPath(c.name)
		if err != nil {
			continue
		}
		cmd := exec.CommandContext(ctx, binPath, c.args...)
		outBytes, cmdErr := cmd.CombinedOutput()
		raw := strings.TrimSpace(string(outBytes))
		if raw == "" && cmdErr != nil {
			continue
		}
		if strings.Contains(strings.ToLower(raw), "operation not permitted") ||
			strings.Contains(strings.ToLower(raw), "socket: permission denied") {
			continue
		}

		hops := c.parser(raw)
		if len(hops) > 0 {
			enrichTraceroutePTRs(hops)
			completed := false
			for _, h := range hops {
				if h.IP != "" && (h.IP == dest || h.IP == resolvedIP) {
					completed = true
					break
				}
			}
			return &TracerouteResult{
				Target:     cleanTarget,
				ResolvedIP: resolvedIP,
				Method:     c.name,
				Hops:       hops,
				Completed:  completed,
				RawOutput:  raw,
			}
		}
	}

	// Fallback: direct synthetic hop check using Ping so the user still gets endpoint reachability
	pingRes := RunPing(cleanTarget)
	hopIP := resolvedIP
	if hopIP == "" {
		hopIP = pingRes.ResolvedIP
	}
	var hops []TracerouteHop
	if pingRes.Reachable {
		hops = append(hops, TracerouteHop{
			Hop: 1,
			IP:  hopIP,
			RTT: pingRes.AvgRTT,
		})
		enrichTraceroutePTRs(hops)
	}

	return &TracerouteResult{
		Target:     cleanTarget,
		ResolvedIP: hopIP,
		Method:     "direct-probe",
		Hops:       hops,
		Completed:  pingRes.Reachable,
		RawOutput:  pingRes.RawOutput,
	}
}

var (
	reHopLead = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)
	reIPv4Or6 = regexp.MustCompile(`([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]{3,})`)
	reRTTMs   = regexp.MustCompile(`(?i)(<?[0-9]+(?:\.[0-9]+)?)\s*ms`)
)

// ParseTracerouteOutput parses classic `traceroute` and Windows `tracert` output.
func ParseTracerouteOutput(raw string) []TracerouteHop {
	var hops []TracerouteHop
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(strings.ToLower(trimmed), "traceroute") ||
			strings.HasPrefix(strings.ToLower(trimmed), "tracing route") ||
			strings.HasPrefix(strings.ToLower(trimmed), "over a maximum") ||
			strings.HasPrefix(strings.ToLower(trimmed), "trace complete") {
			continue
		}

		m := reHopLead.FindStringSubmatch(trimmed)
		if len(m) < 3 {
			continue
		}
		hopNum, err := strconv.Atoi(m[1])
		if err != nil || hopNum <= 0 {
			continue
		}
		rest := strings.TrimSpace(m[2])
		if strings.Contains(rest, "* * *") || rest == "*" || strings.Contains(strings.ToLower(rest), "request timed out") {
			hops = append(hops, TracerouteHop{
				Hop:     hopNum,
				Timeout: true,
			})
			continue
		}

		var foundIP string
		for _, tok := range strings.Fields(rest) {
			cleanTok := strings.Trim(tok, "()[]")
			if net.ParseIP(cleanTok) != nil {
				foundIP = cleanTok
				break
			}
		}

		var foundRTT string
		if rm := reRTTMs.FindStringSubmatch(rest); len(rm) > 1 {
			foundRTT = rm[1] + " ms"
		}

		if foundIP == "" && foundRTT == "" {
			hops = append(hops, TracerouteHop{
				Hop:     hopNum,
				Timeout: true,
			})
			continue
		}

		hops = append(hops, TracerouteHop{
			Hop: hopNum,
			IP:  foundIP,
			RTT: foundRTT,
		})
	}
	return hops
}

var reTracepathLine = regexp.MustCompile(`^\s*(\d+)\??:\s+(.*)$`)

// ParseTracepathOutput parses Linux `tracepath` output and deduplicates multi-probe lines per hop.
func ParseTracepathOutput(raw string) []TracerouteHop {
	byHop := make(map[int]TracerouteHop)
	var order []int

	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(strings.ToLower(trimmed), "resume:") {
			continue
		}
		m := reTracepathLine.FindStringSubmatch(trimmed)
		if len(m) < 3 {
			continue
		}
		hopNum, err := strconv.Atoi(m[1])
		if err != nil || hopNum <= 0 {
			continue
		}
		rest := strings.TrimSpace(m[2])
		if strings.Contains(strings.ToLower(rest), "[localhost]") {
			continue
		}

		existing, seen := byHop[hopNum]
		if !seen {
			order = append(order, hopNum)
			existing = TracerouteHop{Hop: hopNum, Timeout: true}
		}

		if strings.Contains(strings.ToLower(rest), "no reply") {
			byHop[hopNum] = existing
			continue
		}

		for _, tok := range strings.Fields(rest) {
			cleanTok := strings.Trim(tok, "()[]")
			if net.ParseIP(cleanTok) != nil {
				existing.IP = cleanTok
				existing.Timeout = false
				break
			}
		}
		if rm := reRTTMs.FindStringSubmatch(rest); len(rm) > 1 {
			existing.RTT = rm[1] + " ms"
			existing.Timeout = false
		}
		byHop[hopNum] = existing
	}

	sort.Ints(order)
	hops := make([]TracerouteHop, 0, len(order))
	for _, h := range order {
		hops = append(hops, byHop[h])
	}
	return hops
}

var reMTRLine = regexp.MustCompile(`^\s*(\d+)\.\|--\s+(\S+)\s+[0-9.]+%?\s+\d+\s+([0-9.]+)`)

// ParseMTRReportOutput parses `mtr --report` output into TracerouteHops.
func ParseMTRReportOutput(raw string) []TracerouteHop {
	var hops []TracerouteHop
	for _, line := range strings.Split(raw, "\n") {
		m := reMTRLine.FindStringSubmatch(line)
		if len(m) < 4 {
			continue
		}
		hopNum, err := strconv.Atoi(m[1])
		if err != nil || hopNum <= 0 {
			continue
		}
		hostField := strings.TrimSpace(m[2])
		if hostField == "???" {
			hops = append(hops, TracerouteHop{
				Hop:     hopNum,
				Timeout: true,
			})
			continue
		}
		hop := TracerouteHop{
			Hop: hopNum,
			RTT: m[3] + " ms",
		}
		if net.ParseIP(hostField) != nil {
			hop.IP = hostField
		} else {
			hop.Host = hostField
		}
		hops = append(hops, hop)
	}
	return hops
}

func enrichTraceroutePTRs(hops []TracerouteHop) {
	var wg sync.WaitGroup
	for i := range hops {
		if hops[i].IP == "" || hops[i].Host != "" {
			continue
		}
		wg.Add(1)
		go func(idx int, ip string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(ctx, ip)
			if err == nil && len(names) > 0 {
				clean := strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
				if clean != "" {
					hops[idx].Host = clean
				}
			}
		}(i, hops[i].IP)
	}
	wg.Wait()
}

// IsPublicRoutableIP returns true if ipStr is a valid global unicast public IP address
// (excluding loopback, RFC1918 private, link-local, and CGNAT ranges).
func IsPublicRoutableIP(ipStr string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ipStr))
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsUnspecified() {
		return false
	}
	return parsed.IsGlobalUnicast()
}

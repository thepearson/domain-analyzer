package analyzer

import (
	"net"
	"testing"
)

func TestGrabBannerLocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_Test\r\n"))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	banner := grabBanner(conn, "127.0.0.1", 22)
	if banner != "SSH-2.0-OpenSSH_Test" {
		t.Errorf("expected banner 'SSH-2.0-OpenSSH_Test', got %q", banner)
	}
}

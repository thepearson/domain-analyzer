package storage

import (
	"path/filepath"
	"strings"
	"testing"

	"domain-analyzer/analyzer"
)

func TestStoreSaveTreeAndChildDeduplication(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_scans.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	dom := &analyzer.DomainInfo{
		Domain:     "example.com",
		ApexDomain: "example.com",
		DNS: analyzer.DNSInfo{
			IPAddress:   "93.184.216.34",
			Nameservers: []string{"ns1.example.com"},
		},
		WAF: analyzer.WAFInfo{
			Detected: true,
			Summary:  "Cloudflare (Enforcing)",
		},
	}

	// 1. Save top-level scan
	rootID, err := store.SaveDomainScan(dom, 0, "", true)
	if err != nil {
		t.Fatalf("SaveDomainScan failed: %v", err)
	}

	// 2. Save child domain scan (Nameserver)
	nsDomain := &analyzer.DomainInfo{
		Domain:     "ns1.example.com",
		ApexDomain: "example.com",
		DNS: analyzer.DNSInfo{
			IPAddress: "198.51.100.10",
		},
	}
	childID, err := store.SaveDomainScan(nsDomain, rootID, "Nameserver", false)
	if err != nil {
		t.Fatalf("SaveDomainScan (child) failed: %v", err)
	}

	// 3. Re-scanning the same child under rootID should update the existing child scan in place
	nsDomainUpdated := &analyzer.DomainInfo{
		Domain:     "ns1.example.com",
		ApexDomain: "example.com",
		Registrar:  "Updated Registrar",
		DNS: analyzer.DNSInfo{
			IPAddress: "198.51.100.10",
		},
	}
	childID2, err := store.SaveDomainScan(nsDomainUpdated, rootID, "Nameserver", false)
	if err != nil {
		t.Fatalf("SaveDomainScan (rescan child) failed: %v", err)
	}
	if childID2 != childID {
		t.Errorf("expected rescanning child to update existing childID %d, got new ID %d", childID, childID2)
	}

	// 4. Save a grandchild IP scan (with port scan data) under the child nameserver scan
	nsIP := &analyzer.IPInfo{
		IP:          "198.51.100.10",
		Owner:       "Example NS Net",
		ASN:         "AS64496",
		PortScanned: true,
		OpenPorts: []analyzer.PortService{
			{Port: 53, Service: "DNS", State: "open"},
			{Port: 443, Service: "HTTPS", State: "open"},
		},
	}
	grandchildID, err := store.SaveIPScan(nsIP, childID, "A Record", false)
	if err != nil {
		t.Fatalf("SaveIPScan (grandchild) failed: %v", err)
	}

	// 5. Verify multiple top-level scans of the same domain are still allowed
	secondRootID, err := store.SaveDomainScan(dom, 0, "", false)
	if err != nil {
		t.Fatalf("SaveDomainScan (second top-level) failed: %v", err)
	}
	if secondRootID == rootID {
		t.Errorf("expected second top-level scan to get a new ID, got %d", secondRootID)
	}

	// 6. Verify ListScans returns hierarchical tree order with proper Depth
	scans, err := store.ListScans("")
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(scans) != 4 {
		t.Fatalf("expected 4 total scans (2 roots, 1 child, 1 grandchild), got %d", len(scans))
	}
	// First item is newest root (secondRootID, Depth 0)
	// Second item is first root (rootID, Depth 0)
	// Third item is child (childID, Depth 1)
	// Fourth item is grandchild (grandchildID, Depth 2)
	if scans[0].ID != secondRootID || scans[0].Depth != 0 {
		t.Errorf("unexpected scans[0]: %+v", scans[0])
	}
	if scans[1].ID != rootID || scans[1].Depth != 0 || scans[1].ChildCount != 1 {
		t.Errorf("unexpected scans[1]: %+v", scans[1])
	}
	if scans[2].ID != childID || scans[2].Depth != 1 || scans[2].ChildCount != 1 {
		t.Errorf("unexpected scans[2]: %+v", scans[2])
	}
	if scans[3].ID != grandchildID || scans[3].Depth != 2 {
		t.Errorf("unexpected scans[3]: %+v", scans[3])
	}

	// 7. Verify top-level JSON export recursively includes child and grandchild scan data
	gotRoot, err := store.GetScan(rootID)
	if err != nil {
		t.Fatalf("GetScan(rootID) failed: %v", err)
	}
	if !strings.Contains(gotRoot.RawJSON, `"child_scans"`) ||
		!strings.Contains(gotRoot.RawJSON, `"ns1.example.com"`) ||
		!strings.Contains(gotRoot.RawJSON, `"198.51.100.10"`) ||
		!strings.Contains(gotRoot.RawJSON, `"open_ports"`) {
		t.Errorf("expected top-level RawJSON to include nested child and grandchild port scan data, got:\n%s", gotRoot.RawJSON)
	}

	// 8. Verify deleting rootID deletes its child and grandchild scans
	if err := store.DeleteScan(rootID); err != nil {
		t.Fatalf("DeleteScan(rootID) failed: %v", err)
	}
	remaining, _ := store.ListScans("")
	if len(remaining) != 1 || remaining[0].ID != secondRootID {
		t.Errorf("expected only secondRootID to remain after deleting rootID, got %+v", remaining)
	}
}

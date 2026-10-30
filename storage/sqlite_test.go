package storage

import (
	"path/filepath"
	"testing"

	"domain-analyzer/analyzer"
)

func TestStoreSaveAndLineage(t *testing.T) {
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
			IPAddress: "93.184.216.34",
		},
		WAF: analyzer.WAFInfo{
			Detected: true,
			Summary:  "Cloudflare (Enforcing)",
		},
	}

	parentID, err := store.SaveDomainScan(dom, 0, "", true)
	if err != nil {
		t.Fatalf("SaveDomainScan failed: %v", err)
	}

	ipScan := &analyzer.IPInfo{
		IP:         "93.184.216.34",
		Owner:      "Edgecast Inc.",
		ASN:        "AS15133",
		PTRRecords: []string{"edge.example.com"},
	}

	childID, err := store.SaveIPScan(ipScan, parentID, "A Record", false)
	if err != nil {
		t.Fatalf("SaveIPScan failed: %v", err)
	}

	scans, err := store.ListScans("")
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(scans) != 2 {
		t.Fatalf("expected 2 scans, got %d", len(scans))
	}

	// Newest scan should be first
	if scans[0].ID != childID || scans[0].TargetType != analyzer.TargetTypeIP {
		t.Errorf("unexpected first scan: %+v", scans[0])
	}

	// Verify child lineage
	children, err := store.GetChildScans(parentID)
	if err != nil {
		t.Fatalf("GetChildScans failed: %v", err)
	}
	if len(children) != 1 || children[0].ID != childID || children[0].PivotReason != "A Record" {
		t.Errorf("unexpected children: %+v", children)
	}

	// Verify GetScan deserialization
	gotParent, err := store.GetScan(parentID)
	if err != nil || gotParent.DomainInfo == nil || gotParent.DomainInfo.DNS.IPAddress != "93.184.216.34" {
		t.Errorf("GetScan(parentID) failed or missing DomainInfo: %+v, err=%v", gotParent, err)
	}

	gotChild, err := store.GetScan(childID)
	if err != nil || gotChild.IPInfo == nil || gotChild.IPInfo.ASN != "AS15133" {
		t.Errorf("GetScan(childID) failed or missing IPInfo: %+v, err=%v", gotChild, err)
	}

	// Verify LatestScansByTarget
	latest, err := store.LatestScansByTarget()
	if err != nil {
		t.Fatalf("LatestScansByTarget failed: %v", err)
	}
	if latest["example.com"] != parentID || latest["93.184.216.34"] != childID {
		t.Errorf("unexpected LatestScansByTarget map: %+v", latest)
	}

	// Verify DeleteScan
	if err := store.DeleteScan(childID); err != nil {
		t.Fatalf("DeleteScan failed: %v", err)
	}
	scansAfter, _ := store.ListScans("")
	if len(scansAfter) != 1 {
		t.Errorf("expected 1 scan after deletion, got %d", len(scansAfter))
	}
}

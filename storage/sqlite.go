package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"domain-analyzer/analyzer"
	_ "modernc.org/sqlite"
)

type ScanSummary struct {
	ID           int64               `json:"id"`
	Target       string              `json:"target"`
	TargetType   analyzer.TargetType `json:"target_type"`
	ParentScanID int64               `json:"parent_scan_id,omitempty"`
	PivotReason  string              `json:"pivot_reason,omitempty"`
	CheckVulns   bool                `json:"check_vulns"`
	Summary      string              `json:"summary"`
	Favicon      []byte              `json:"favicon,omitempty"`
	CreatedAt    time.Time           `json:"created_at"`
}

type ScanRecord struct {
	ScanSummary
	DomainInfo *analyzer.DomainInfo `json:"domain_info,omitempty"`
	IPInfo     *analyzer.IPInfo     `json:"ip_info,omitempty"`
	RawJSON    string               `json:"raw_json"`
}

type Store struct {
	db *sql.DB
}

// DefaultDBPath returns the platform-appropriate application data path for the SQLite database.
func DefaultDBPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil || configDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "domain-analyzer-scans.db", nil
		}
		configDir = filepath.Join(homeDir, ".config")
	}
	appDir := filepath.Join(configDir, "domain-analyzer")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		return "", fmt.Errorf("creating config dir: %w", err)
	}
	return filepath.Join(appDir, "scans.db"), nil
}

// Open opens or initializes the SQLite scan database at dbPath.
func Open(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db: %w", err)
	}
	db.SetMaxOpenConns(1)

	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		target_type TEXT NOT NULL,
		parent_scan_id INTEGER NOT NULL DEFAULT 0,
		pivot_reason TEXT NOT NULL DEFAULT '',
		check_vulns INTEGER NOT NULL DEFAULT 0,
		summary TEXT NOT NULL DEFAULT '',
		favicon BLOB,
		payload_json TEXT NOT NULL,
		created_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
	CREATE INDEX IF NOT EXISTS idx_scans_parent ON scans(parent_scan_id);
	CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Upgrade existing databases created before the favicon column was added
	_, _ = s.db.Exec(`ALTER TABLE scans ADD COLUMN favicon BLOB`)
	return nil
}

func buildDomainSummary(info *analyzer.DomainInfo) string {
	if info == nil {
		return ""
	}
	var parts []string
	if info.DNS.IPAddress != "" {
		parts = append(parts, "IP: "+info.DNS.IPAddress)
	}
	if info.WAF.Detected {
		parts = append(parts, "WAF: "+info.WAF.Summary)
	} else {
		parts = append(parts, "No WAF")
	}
	if len(info.Vulnerabilities) > 0 {
		parts = append(parts, fmt.Sprintf("%d CVEs", len(info.Vulnerabilities)))
	}
	return strings.Join(parts, " • ")
}

func buildIPSummary(info *analyzer.IPInfo) string {
	if info == nil {
		return ""
	}
	var parts []string
	if info.Owner != "" {
		parts = append(parts, info.Owner)
	}
	if info.ASN != "" {
		parts = append(parts, info.ASN)
	}
	if len(info.PTRRecords) > 0 {
		parts = append(parts, "PTR: "+info.PTRRecords[0])
	}
	if len(parts) == 0 {
		return "IP Reconnaissance"
	}
	return strings.Join(parts, " • ")
}

// SaveDomainScan persists a completed DomainInfo scan and returns its new scan ID.
func (s *Store) SaveDomainScan(info *analyzer.DomainInfo, parentID int64, reason string, checkVulns bool) (int64, error) {
	if info == nil {
		return 0, fmt.Errorf("domain info is nil")
	}
	favicon := info.Web.Favicon
	// Temporarily omit binary favicon from JSON payload so Raw JSON view stays clean and human-readable
	info.Web.Favicon = nil
	payload, err := json.MarshalIndent(info, "", "  ")
	info.Web.Favicon = favicon
	if err != nil {
		return 0, fmt.Errorf("marshaling domain info: %w", err)
	}

	target := strings.ToLower(strings.TrimSpace(info.Domain))
	summary := buildDomainSummary(info)
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	vulnsInt := 0
	if checkVulns {
		vulnsInt = 1
	}

	res, err := s.db.Exec(
		`INSERT INTO scans (target, target_type, parent_scan_id, pivot_reason, check_vulns, summary, favicon, payload_json, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		target, string(analyzer.TargetTypeDomain), parentID, reason, vulnsInt, summary, favicon, string(payload), createdAt,
	)
	if err != nil {
		return 0, fmt.Errorf("inserting domain scan: %w", err)
	}
	return res.LastInsertId()
}

// SaveIPScan persists a completed IPInfo scan and returns its new scan ID.
func (s *Store) SaveIPScan(info *analyzer.IPInfo, parentID int64, reason string, checkVulns bool) (int64, error) {
	if info == nil {
		return 0, fmt.Errorf("ip info is nil")
	}
	favicon := info.Web.Favicon
	info.Web.Favicon = nil
	payload, err := json.MarshalIndent(info, "", "  ")
	info.Web.Favicon = favicon
	if err != nil {
		return 0, fmt.Errorf("marshaling ip info: %w", err)
	}

	target := strings.TrimSpace(info.IP)
	summary := buildIPSummary(info)
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	vulnsInt := 0
	if checkVulns {
		vulnsInt = 1
	}

	res, err := s.db.Exec(
		`INSERT INTO scans (target, target_type, parent_scan_id, pivot_reason, check_vulns, summary, favicon, payload_json, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		target, string(analyzer.TargetTypeIP), parentID, reason, vulnsInt, summary, favicon, string(payload), createdAt,
	)
	if err != nil {
		return 0, fmt.Errorf("inserting ip scan: %w", err)
	}
	return res.LastInsertId()
}

// ListScans returns all saved scans ordered from newest to oldest, optionally filtered by target or summary text.
func (s *Store) ListScans(searchFilter string) ([]ScanSummary, error) {
	filter := strings.TrimSpace(searchFilter)
	var rows *sql.Rows
	var err error
	if filter == "" {
		rows, err = s.db.Query(
			`SELECT id, target, target_type, parent_scan_id, pivot_reason, check_vulns, summary, favicon, created_at
			 FROM scans ORDER BY id DESC`,
		)
	} else {
		like := "%" + strings.ToLower(filter) + "%"
		rows, err = s.db.Query(
			`SELECT id, target, target_type, parent_scan_id, pivot_reason, check_vulns, summary, favicon, created_at
			 FROM scans
			 WHERE LOWER(target) LIKE ? OR LOWER(summary) LIKE ? OR LOWER(pivot_reason) LIKE ?
			 ORDER BY id DESC`,
			like, like, like,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanSummariesFromRows(rows)
}

// GetChildScans returns all scans that were drilled down directly from parentID.
func (s *Store) GetChildScans(parentID int64) ([]ScanSummary, error) {
	if parentID <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(
		`SELECT id, target, target_type, parent_scan_id, pivot_reason, check_vulns, summary, favicon, created_at
		 FROM scans WHERE parent_scan_id = ? ORDER BY id DESC`,
		parentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanSummariesFromRows(rows)
}

func scanSummariesFromRows(rows *sql.Rows) ([]ScanSummary, error) {
	var out []ScanSummary
	for rows.Next() {
		var item ScanSummary
		var targetType string
		var vulnsInt int
		var createdStr string
		if err := rows.Scan(
			&item.ID,
			&item.Target,
			&targetType,
			&item.ParentScanID,
			&item.PivotReason,
			&vulnsInt,
			&item.Summary,
			&item.Favicon,
			&createdStr,
		); err != nil {
			return nil, err
		}
		item.TargetType = analyzer.TargetType(targetType)
		item.CheckVulns = vulnsInt != 0
		if t, err := time.Parse(time.RFC3339Nano, createdStr); err == nil {
			item.CreatedAt = t
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// GetScan retrieves the full ScanRecord (including deserialized DomainInfo or IPInfo) by ID.
func (s *Store) GetScan(id int64) (*ScanRecord, error) {
	var rec ScanRecord
	var targetType string
	var vulnsInt int
	var createdStr string

	err := s.db.QueryRow(
		`SELECT id, target, target_type, parent_scan_id, pivot_reason, check_vulns, summary, favicon, payload_json, created_at
		 FROM scans WHERE id = ?`,
		id,
	).Scan(
		&rec.ID,
		&rec.Target,
		&targetType,
		&rec.ParentScanID,
		&rec.PivotReason,
		&vulnsInt,
		&rec.Summary,
		&rec.Favicon,
		&rec.RawJSON,
		&createdStr,
	)
	if err != nil {
		return nil, err
	}

	rec.TargetType = analyzer.TargetType(targetType)
	rec.CheckVulns = vulnsInt != 0
	if t, err := time.Parse(time.RFC3339Nano, createdStr); err == nil {
		rec.CreatedAt = t
	}

	// Ensure RawJSON is pretty-formatted even if loaded from an older compact record
	var prettyBuf strings.Builder
	var rawAny any
	if err := json.Unmarshal([]byte(rec.RawJSON), &rawAny); err == nil {
		if indented, err := json.MarshalIndent(rawAny, "", "  "); err == nil {
			prettyBuf.Write(indented)
			rec.RawJSON = prettyBuf.String()
		}
	}

	if rec.TargetType == analyzer.TargetTypeIP {
		var ipInfo analyzer.IPInfo
		if err := json.Unmarshal([]byte(rec.RawJSON), &ipInfo); err != nil {
			return nil, fmt.Errorf("unmarshaling ip scan %d: %w", id, err)
		}
		ipInfo.Web.Favicon = rec.Favicon
		rec.IPInfo = &ipInfo
	} else {
		var domInfo analyzer.DomainInfo
		if err := json.Unmarshal([]byte(rec.RawJSON), &domInfo); err != nil {
			return nil, fmt.Errorf("unmarshaling domain scan %d: %w", id, err)
		}
		domInfo.Web.Favicon = rec.Favicon
		rec.DomainInfo = &domInfo
	}

	return &rec, nil
}

// LatestScansByTarget returns a map of normalized target -> most recent scan ID.
func (s *Store) LatestScansByTarget() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT target, MAX(id) FROM scans GROUP BY target`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[string]int64)
	for rows.Next() {
		var target string
		var id int64
		if err := rows.Scan(&target, &id); err != nil {
			return nil, err
		}
		res[strings.ToLower(strings.TrimSpace(target))] = id
	}
	return res, rows.Err()
}

// DeleteScan removes a scan by ID.
func (s *Store) DeleteScan(id int64) error {
	_, err := s.db.Exec(`DELETE FROM scans WHERE id = ?`, id)
	return err
}

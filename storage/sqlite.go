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
	Depth        int                 `json:"depth,omitempty"`
	IsLastChild  bool                `json:"is_last_child,omitempty"`
	ChildCount   int                 `json:"child_count,omitempty"`
}

type ChildScanExport struct {
	ID          int64                `json:"id"`
	Target      string               `json:"target"`
	TargetType  analyzer.TargetType  `json:"target_type"`
	PivotReason string               `json:"pivot_reason,omitempty"`
	CreatedAt   string               `json:"created_at"`
	DomainScan  *analyzer.DomainInfo `json:"domain_scan,omitempty"`
	IPScan      *analyzer.IPInfo     `json:"ip_scan,omitempty"`
	ChildScans  []ChildScanExport    `json:"child_scans,omitempty"`
}

type domainExportWithChildren struct {
	*analyzer.DomainInfo
	ChildScans []ChildScanExport `json:"child_scans,omitempty"`
}

type ipExportWithChildren struct {
	*analyzer.IPInfo
	ChildScans []ChildScanExport `json:"child_scans,omitempty"`
}

type ScanRecord struct {
	ScanSummary
	DomainInfo *analyzer.DomainInfo `json:"domain_info,omitempty"`
	IPInfo     *analyzer.IPInfo     `json:"ip_info,omitempty"`
	ChildTree  []ChildScanExport    `json:"child_scans,omitempty"`
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
			return "reconnascan-scans.db", nil
		}
		configDir = filepath.Join(homeDir, ".config")
	}
	appDir := filepath.Join(configDir, "reconnascan")
	oldDir := filepath.Join(configDir, "domain-analyzer")
	if _, err := os.Stat(appDir); os.IsNotExist(err) {
		if _, errOld := os.Stat(oldDir); errOld == nil {
			// Migrate/reuse existing directory if reconnascan doesn't exist yet
			appDir = oldDir
		}
	}
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
	if info.Subdomains != nil && len(info.Subdomains.Subdomains) > 0 {
		parts = append(parts, fmt.Sprintf("%d subdomains", len(info.Subdomains.Subdomains)))
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
	if info.PortScanned {
		parts = append(parts, fmt.Sprintf("%d open ports", len(info.OpenPorts)))
	}
	if len(parts) == 0 {
		return "IP Reconnaissance"
	}
	return strings.Join(parts, " • ")
}

// SaveDomainScan persists a completed DomainInfo scan.
// If parentID > 0 and a child scan for the same target already exists under parentID, it updates that child scan in place.
// Top-level scans (parentID == 0) always create a new record so multiple top-level scans of the same domain are supported.
func (s *Store) SaveDomainScan(info *analyzer.DomainInfo, parentID int64, reason string, checkVulns bool) (int64, error) {
	if info == nil {
		return 0, fmt.Errorf("domain info is nil")
	}
	target := strings.ToLower(strings.TrimSpace(info.Domain))

	if parentID > 0 {
		var existingID int64
		err := s.db.QueryRow(
			`SELECT id FROM scans WHERE parent_scan_id = ? AND LOWER(target) = ? LIMIT 1`,
			parentID, target,
		).Scan(&existingID)
		if err == nil && existingID > 0 {
			if err := s.UpdateDomainScan(existingID, info, reason, checkVulns); err != nil {
				return 0, err
			}
			return existingID, nil
		}
	}

	favicon := info.Web.Favicon
	info.Web.Favicon = nil
	payload, err := json.MarshalIndent(info, "", "  ")
	info.Web.Favicon = favicon
	if err != nil {
		return 0, fmt.Errorf("marshaling domain info: %w", err)
	}

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

// UpdateDomainScan updates an existing domain scan record in place.
func (s *Store) UpdateDomainScan(id int64, info *analyzer.DomainInfo, reason string, checkVulns bool) error {
	if info == nil {
		return fmt.Errorf("domain info is nil")
	}
	if info.Ping == nil || info.Traceroute == nil || info.Subdomains == nil || info.Metadata == nil || info.HTTPTrace == nil || info.ZoneAudit == nil || info.Reputation == nil || !info.VulnsChecked || !info.Email.DeepChecked {
		if existingRec, err := s.GetScan(id); err == nil && existingRec.DomainInfo != nil {
			if info.Ping == nil {
				info.Ping = existingRec.DomainInfo.Ping
			}
			if info.Traceroute == nil {
				info.Traceroute = existingRec.DomainInfo.Traceroute
			}
			if info.Subdomains == nil {
				info.Subdomains = existingRec.DomainInfo.Subdomains
			}
			if info.Metadata == nil {
				info.Metadata = existingRec.DomainInfo.Metadata
			}
			if info.HTTPTrace == nil {
				info.HTTPTrace = existingRec.DomainInfo.HTTPTrace
			}
			if info.ZoneAudit == nil {
				info.ZoneAudit = existingRec.DomainInfo.ZoneAudit
			}
			if info.Reputation == nil {
				info.Reputation = existingRec.DomainInfo.Reputation
			}
			if !info.VulnsChecked && existingRec.DomainInfo.VulnsChecked {
				info.VulnsChecked = true
				info.Vulnerabilities = existingRec.DomainInfo.Vulnerabilities
				checkVulns = true
			}
			if !info.Email.DeepChecked && existingRec.DomainInfo.Email.DeepChecked {
				info.Email.DeepChecked = true
				if len(info.Email.MXRecords) == 0 {
					info.Email.MXRecords = existingRec.DomainInfo.Email.MXRecords
				}
				if len(info.Email.DKIMRecords) == 0 {
					info.Email.DKIMRecords = existingRec.DomainInfo.Email.DKIMRecords
				}
				if info.Email.MTASTS == nil {
					info.Email.MTASTS = existingRec.DomainInfo.Email.MTASTS
				}
				if info.Email.TLSRPT == nil {
					info.Email.TLSRPT = existingRec.DomainInfo.Email.TLSRPT
				}
				if info.Email.BIMI == nil {
					info.Email.BIMI = existingRec.DomainInfo.Email.BIMI
				}
			}
		}
	}
	favicon := info.Web.Favicon
	info.Web.Favicon = nil
	payload, err := json.MarshalIndent(info, "", "  ")
	info.Web.Favicon = favicon
	if err != nil {
		return fmt.Errorf("marshaling domain info: %w", err)
	}

	summary := buildDomainSummary(info)
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	vulnsInt := 0
	if checkVulns {
		vulnsInt = 1
	}

	if reason != "" {
		_, err = s.db.Exec(
			`UPDATE scans SET pivot_reason = ?, check_vulns = ?, summary = ?, favicon = ?, payload_json = ?, created_at = ? WHERE id = ?`,
			reason, vulnsInt, summary, favicon, string(payload), createdAt, id,
		)
	} else {
		_, err = s.db.Exec(
			`UPDATE scans SET check_vulns = ?, summary = ?, favicon = ?, payload_json = ?, created_at = ? WHERE id = ?`,
			vulnsInt, summary, favicon, string(payload), createdAt, id,
		)
	}
	return err
}

// SaveIPScan persists a completed IPInfo scan.
// If parentID > 0 and a child scan for the same IP already exists under parentID, it updates that child scan in place.
func (s *Store) SaveIPScan(info *analyzer.IPInfo, parentID int64, reason string, checkVulns bool) (int64, error) {
	if info == nil {
		return 0, fmt.Errorf("ip info is nil")
	}
	target := strings.TrimSpace(info.IP)

	if parentID > 0 {
		var existingID int64
		err := s.db.QueryRow(
			`SELECT id FROM scans WHERE parent_scan_id = ? AND LOWER(target) = ? LIMIT 1`,
			parentID, strings.ToLower(target),
		).Scan(&existingID)
		if err == nil && existingID > 0 {
			// Preserve existing port scan results if the new IP scan did not run a port scan
			if !info.PortScanned {
				if existingRec, err := s.GetScan(existingID); err == nil && existingRec.IPInfo != nil && existingRec.IPInfo.PortScanned {
					info.PortScanned = true
					info.OpenPorts = existingRec.IPInfo.OpenPorts
				}
			}
			if err := s.UpdateIPScan(existingID, info, reason, checkVulns); err != nil {
				return 0, err
			}
			return existingID, nil
		}
	}

	favicon := info.Web.Favicon
	info.Web.Favicon = nil
	payload, err := json.MarshalIndent(info, "", "  ")
	info.Web.Favicon = favicon
	if err != nil {
		return 0, fmt.Errorf("marshaling ip info: %w", err)
	}

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

// UpdateIPScan updates an existing IP scan record in place (e.g., when rescanning a child IP or saving port scan results).
func (s *Store) UpdateIPScan(id int64, info *analyzer.IPInfo, reason string, checkVulns bool) error {
	if info == nil {
		return fmt.Errorf("ip info is nil")
	}
	if !info.PortScanned || info.Ping == nil || info.Traceroute == nil || info.Metadata == nil || info.HTTPTrace == nil || info.Reputation == nil || !info.VulnsChecked {
		if existingRec, err := s.GetScan(id); err == nil && existingRec.IPInfo != nil {
			if !info.PortScanned && existingRec.IPInfo.PortScanned {
				info.PortScanned = true
				info.OpenPorts = existingRec.IPInfo.OpenPorts
			}
			if info.Ping == nil {
				info.Ping = existingRec.IPInfo.Ping
			}
			if info.Traceroute == nil {
				info.Traceroute = existingRec.IPInfo.Traceroute
			}
			if info.Metadata == nil {
				info.Metadata = existingRec.IPInfo.Metadata
			}
			if info.HTTPTrace == nil {
				info.HTTPTrace = existingRec.IPInfo.HTTPTrace
			}
			if info.Reputation == nil {
				info.Reputation = existingRec.IPInfo.Reputation
			}
			if !info.VulnsChecked && existingRec.IPInfo.VulnsChecked {
				info.VulnsChecked = true
				info.Vulnerabilities = existingRec.IPInfo.Vulnerabilities
				checkVulns = true
			}
		}
	}
	favicon := info.Web.Favicon
	info.Web.Favicon = nil
	payload, err := json.MarshalIndent(info, "", "  ")
	info.Web.Favicon = favicon
	if err != nil {
		return fmt.Errorf("marshaling ip info: %w", err)
	}

	summary := buildIPSummary(info)
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	vulnsInt := 0
	if checkVulns {
		vulnsInt = 1
	}

	if reason != "" {
		_, err = s.db.Exec(
			`UPDATE scans SET pivot_reason = ?, check_vulns = ?, summary = ?, favicon = ?, payload_json = ?, created_at = ? WHERE id = ?`,
			reason, vulnsInt, summary, favicon, string(payload), createdAt, id,
		)
	} else {
		_, err = s.db.Exec(
			`UPDATE scans SET check_vulns = ?, summary = ?, favicon = ?, payload_json = ?, created_at = ? WHERE id = ?`,
			vulnsInt, summary, favicon, string(payload), createdAt, id,
		)
	}
	return err
}

// enrichWebTechDetails ensures every detected technology has its TechDetail entry and Website URL populated.
func enrichWebTechDetails(web *analyzer.WebInfo) {
	if web == nil {
		return
	}
	if len(web.TechDetails) == 0 && len(web.TechStack) > 0 {
		for _, name := range web.TechStack {
			site, icon := analyzer.LookupTechAppInfo(name)
			web.TechDetails = append(web.TechDetails, analyzer.TechDetail{
				Name:    name,
				Website: site,
				Icon:    icon,
			})
		}
		return
	}
	for i := range web.TechDetails {
		if web.TechDetails[i].Website == "" {
			site, icon := analyzer.LookupTechAppInfo(web.TechDetails[i].Name)
			web.TechDetails[i].Website = site
			if web.TechDetails[i].Icon == "" {
				web.TechDetails[i].Icon = icon
			}
		}
	}
}

func cleanWebInfoForRawJSON(web analyzer.WebInfo) analyzer.WebInfo {
	cleaned := web
	cleaned.Favicon = nil
	if len(web.TechDetails) > 0 {
		cleaned.TechDetails = make([]analyzer.TechDetail, len(web.TechDetails))
		for i, td := range web.TechDetails {
			td.Favicon = nil
			cleaned.TechDetails[i] = td
		}
	}
	return cleaned
}

// ListScans returns saved scans arranged as a hierarchical parent -> child -> grandchild tree.
// Top-level scans are ordered newest to oldest, with their child scans nested immediately underneath.
func (s *Store) ListScans(searchFilter string) ([]ScanSummary, error) {
	rows, err := s.db.Query(
		`SELECT id, target, target_type, parent_scan_id, pivot_reason, check_vulns, summary, favicon, created_at
		 FROM scans ORDER BY id DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	all, err := scanSummariesFromRows(rows)
	if err != nil {
		return nil, err
	}

	byID := make(map[int64]ScanSummary, len(all))
	childrenByParent := make(map[int64][]ScanSummary)
	for _, item := range all {
		byID[item.ID] = item
	}

	var roots []ScanSummary
	for _, item := range all {
		if item.ParentScanID > 0 {
			if _, parentExists := byID[item.ParentScanID]; parentExists {
				// Preserve chronological or newest order under parent
				childrenByParent[item.ParentScanID] = append(childrenByParent[item.ParentScanID], item)
				continue
			}
		}
		roots = append(roots, item)
	}

	filter := strings.ToLower(strings.TrimSpace(searchFilter))
	matchesFilter := func(item ScanSummary) bool {
		if filter == "" {
			return true
		}
		return strings.Contains(strings.ToLower(item.Target), filter) ||
			strings.Contains(strings.ToLower(item.Summary), filter) ||
			strings.Contains(strings.ToLower(item.PivotReason), filter)
	}

	var subtreeMatches func(item ScanSummary) bool
	subtreeMatches = func(item ScanSummary) bool {
		if matchesFilter(item) {
			return true
		}
		for _, ch := range childrenByParent[item.ID] {
			if subtreeMatches(ch) {
				return true
			}
		}
		return false
	}

	var ordered []ScanSummary
	visited := make(map[int64]bool)

	var walk func(node ScanSummary, depth int, isLast bool)
	walk = func(node ScanSummary, depth int, isLast bool) {
		if visited[node.ID] {
			return
		}
		visited[node.ID] = true

		kids := childrenByParent[node.ID]
		var visibleKids []ScanSummary
		for _, k := range kids {
			if subtreeMatches(k) {
				visibleKids = append(visibleKids, k)
			}
		}

		node.Depth = depth
		node.IsLastChild = isLast
		node.ChildCount = len(kids)
		ordered = append(ordered, node)

		for i, k := range visibleKids {
			walk(k, depth+1, i == len(visibleKids)-1)
		}
	}

	for _, root := range roots {
		if subtreeMatches(root) {
			walk(root, 0, false)
		}
	}

	return ordered, nil
}

// GetChildScans returns all scans that were drilled down directly from parentID.
func (s *Store) GetChildScans(parentID int64) ([]ScanSummary, error) {
	if parentID <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(
		`SELECT id, target, target_type, parent_scan_id, pivot_reason, check_vulns, summary, favicon, created_at
		 FROM scans WHERE parent_scan_id = ? ORDER BY id ASC`,
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

// buildChildExportTree recursively loads all child and grandchild scans under parentID for JSON export.
func (s *Store) buildChildExportTree(parentID int64, visited map[int64]bool) ([]ChildScanExport, error) {
	if visited[parentID] {
		return nil, nil
	}
	visited[parentID] = true

	rows, err := s.db.Query(
		`SELECT id, target, target_type, pivot_reason, payload_json, created_at
		 FROM scans WHERE parent_scan_id = ? ORDER BY id ASC`,
		parentID,
	)
	if err != nil {
		return nil, err
	}

	type rawChildRow struct {
		id          int64
		target      string
		targetType  string
		pivotReason string
		payloadJSON string
		createdAt   string
	}
	var rawRows []rawChildRow
	for rows.Next() {
		var r rawChildRow
		if err := rows.Scan(&r.id, &r.target, &r.targetType, &r.pivotReason, &r.payloadJSON, &r.createdAt); err != nil {
			rows.Close()
			return nil, err
		}
		rawRows = append(rawRows, r)
	}
	rows.Close()

	var exports []ChildScanExport
	for _, r := range rawRows {
		node := ChildScanExport{
			ID:          r.id,
			Target:      r.target,
			TargetType:  analyzer.TargetType(r.targetType),
			PivotReason: r.pivotReason,
			CreatedAt:   r.createdAt,
		}

		if node.TargetType == analyzer.TargetTypeIP {
			var ipInfo analyzer.IPInfo
			if err := json.Unmarshal([]byte(r.payloadJSON), &ipInfo); err == nil {
				enrichWebTechDetails(&ipInfo.Web)
				ipInfo.Web = cleanWebInfoForRawJSON(ipInfo.Web)
				node.IPScan = &ipInfo
			}
		} else {
			var domInfo analyzer.DomainInfo
			if err := json.Unmarshal([]byte(r.payloadJSON), &domInfo); err == nil {
				enrichWebTechDetails(&domInfo.Web)
				domInfo.Web = cleanWebInfoForRawJSON(domInfo.Web)
				node.DomainScan = &domInfo
			}
		}

		grandchildren, err := s.buildChildExportTree(r.id, visited)
		if err == nil && len(grandchildren) > 0 {
			node.ChildScans = grandchildren
		}
		exports = append(exports, node)
	}

	return exports, nil
}

// GetScan retrieves the full ScanRecord (including deserialized DomainInfo or IPInfo and recursive child_scans JSON) by ID.
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

	visited := make(map[int64]bool)
	childExports, _ := s.buildChildExportTree(rec.ID, visited)
	rec.ChildTree = childExports

	if rec.TargetType == analyzer.TargetTypeIP {
		var ipInfo analyzer.IPInfo
		if err := json.Unmarshal([]byte(rec.RawJSON), &ipInfo); err != nil {
			return nil, fmt.Errorf("unmarshaling ip scan %d: %w", id, err)
		}
		ipInfo.Web.Favicon = rec.Favicon
		enrichWebTechDetails(&ipInfo.Web)
		rec.IPInfo = &ipInfo

		displayCopy := ipInfo
		displayCopy.Web = cleanWebInfoForRawJSON(ipInfo.Web)
		exportObj := ipExportWithChildren{
			IPInfo:     &displayCopy,
			ChildScans: childExports,
		}
		if indented, err := json.MarshalIndent(exportObj, "", "  "); err == nil {
			rec.RawJSON = string(indented)
		}
	} else {
		var domInfo analyzer.DomainInfo
		if err := json.Unmarshal([]byte(rec.RawJSON), &domInfo); err != nil {
			return nil, fmt.Errorf("unmarshaling domain scan %d: %w", id, err)
		}
		domInfo.Web.Favicon = rec.Favicon
		enrichWebTechDetails(&domInfo.Web)
		rec.DomainInfo = &domInfo

		displayCopy := domInfo
		displayCopy.Web = cleanWebInfoForRawJSON(domInfo.Web)
		exportObj := domainExportWithChildren{
			DomainInfo: &displayCopy,
			ChildScans: childExports,
		}
		if indented, err := json.MarshalIndent(exportObj, "", "  "); err == nil {
			rec.RawJSON = string(indented)
		}
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

// DeleteScan removes a scan and any nested child scans beneath it.
func (s *Store) DeleteScan(id int64) error {
	children, _ := s.GetChildScans(id)
	for _, ch := range children {
		_ = s.DeleteScan(ch.ID)
	}
	_, err := s.db.Exec(`DELETE FROM scans WHERE id = ?`, id)
	return err
}

// ClearAllScans deletes all scans and lineage records from the database.
func (s *Store) ClearAllScans() error {
	_, err := s.db.Exec(`DELETE FROM scans`)
	return err
}

// SessionData represents a full exported reconnaissance session containing all scans and lineage trees.
type SessionData struct {
	Version    int           `json:"version"`
	ExportedAt time.Time     `json:"exported_at"`
	Scans      []SessionScan `json:"scans"`
}

// SessionScan represents an individual scan record within an exported session.
type SessionScan struct {
	ID           int64               `json:"id"`
	Target       string              `json:"target"`
	TargetType   analyzer.TargetType `json:"target_type"`
	ParentScanID int64               `json:"parent_scan_id"`
	PivotReason  string              `json:"pivot_reason"`
	CheckVulns   bool                `json:"check_vulns"`
	Summary      string              `json:"summary"`
	Favicon      []byte              `json:"favicon,omitempty"`
	PayloadJSON  string              `json:"payload_json"`
	CreatedAt    string              `json:"created_at"`
}

// ExportSession serializes all scans in the store to a portable JSON byte slice.
func (s *Store) ExportSession() ([]byte, error) {
	rows, err := s.db.Query(
		`SELECT id, target, target_type, parent_scan_id, pivot_reason, check_vulns, summary, favicon, payload_json, created_at
		 FROM scans ORDER BY id ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("querying scans for export: %w", err)
	}
	defer rows.Close()

	var session SessionData
	session.Version = 1
	session.ExportedAt = time.Now().UTC()

	for rows.Next() {
		var item SessionScan
		var targetType string
		var vulnsInt int
		if err := rows.Scan(
			&item.ID,
			&item.Target,
			&targetType,
			&item.ParentScanID,
			&item.PivotReason,
			&vulnsInt,
			&item.Summary,
			&item.Favicon,
			&item.PayloadJSON,
			&item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning session row: %w", err)
		}
		item.TargetType = analyzer.TargetType(targetType)
		item.CheckVulns = vulnsInt != 0
		session.Scans = append(session.Scans, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return json.MarshalIndent(session, "", "  ")
}

// ExportSessionToFile exports all scans to a specified file path.
// If the filePath has no extension, ".rscan" is appended automatically.
func (s *Store) ExportSessionToFile(filePath string) error {
	targetPath := filePath
	if filepath.Ext(targetPath) == "" {
		targetPath += ".rscan"
	}
	data, err := s.ExportSession()
	if err != nil {
		return err
	}
	dir := filepath.Dir(targetPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating directory for session export: %w", err)
		}
	}
	return os.WriteFile(targetPath, data, 0o644)
}

// ImportSession reads and deserializes session JSON data, importing scans while preserving parent-child trees and mapping IDs.
func (s *Store) ImportSession(data []byte) (int, error) {
	var session SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return 0, fmt.Errorf("unmarshaling session json: %w", err)
	}

	oldToNew := make(map[int64]int64)
	importedCount := 0

	for _, scan := range session.Scans {
		parentID := int64(0)
		if scan.ParentScanID > 0 {
			if mapped, ok := oldToNew[scan.ParentScanID]; ok {
				parentID = mapped
			}
		}

		vulnsInt := 0
		if scan.CheckVulns {
			vulnsInt = 1
		}

		res, err := s.db.Exec(
			`INSERT INTO scans (target, target_type, parent_scan_id, pivot_reason, check_vulns, summary, favicon, payload_json, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			scan.Target, string(scan.TargetType), parentID, scan.PivotReason, vulnsInt, scan.Summary, scan.Favicon, scan.PayloadJSON, scan.CreatedAt,
		)
		if err != nil {
			return importedCount, fmt.Errorf("importing scan %s: %w", scan.Target, err)
		}
		newID, _ := res.LastInsertId()
		oldToNew[scan.ID] = newID
		importedCount++
	}

	return importedCount, nil
}

// ImportSessionFromFile loads and imports scans from a .rscan session file.
func (s *Store) ImportSessionFromFile(filePath string) (int, error) {
	targetPath := filePath
	if _, err := os.Stat(targetPath); os.IsNotExist(err) && filepath.Ext(targetPath) == "" {
		if _, errRscan := os.Stat(targetPath + ".rscan"); errRscan == nil {
			targetPath += ".rscan"
		}
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		return 0, fmt.Errorf("reading session file: %w", err)
	}
	return s.ImportSession(data)
}

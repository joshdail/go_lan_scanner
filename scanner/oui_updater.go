package scanner

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultOUIURL = "https://standards-oui.ieee.org/oui/oui.csv"
)

// UpdateOUIDatabase downloads the IEEE CSV, sanitizes it, writes to destPath in the format:
//
//	Header: OUI,OrganizationName
//	Rows:   DC4BA1,Acme Corp
//
// It then calls ReloadVendorDB so in-memory lookups use the new data immediately.
func UpdateOUIDatabase(destPath string) error {
	// Ensure folder exists
	if !filepath.IsAbs(destPath) {
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("mkdir data dir: %w", err)
		}
	}

	client := &http.Client{Timeout: 45 * time.Second}
	req, err := http.NewRequest(http.MethodGet, defaultOUIURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "go-lan-scanner/1.0 (+local)")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download OUI list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from IEEE: %s", resp.Status)
	}

	// Parse incoming CSV (raw IEEE format)
	r := csv.NewReader(resp.Body)

	// Create temp file to write sanitized CSV atomically
	tmpPath := destPath + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create tmp file: %w", err)
	}
	defer func() {
		tmpFile.Close()
		_ = os.Remove(tmpPath) // cleanup on errors
	}()

	w := csv.NewWriter(tmpFile)
	// Write our sanitized header
	if err := w.Write([]string{"OUI", "OrganizationName"}); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Read source header
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("read source header: %w", err)
	}
	// Identify columns (be tolerant to minor header changes)
	colMap := map[string]int{}
	for i, h := range header {
		key := strings.ToLower(strings.TrimSpace(h))
		colMap[key] = i
	}

	// Prefer explicit names; fallback to first two cols
	assignIdx := -1
	orgIdx := -1
	for k, i := range colMap {
		if assignIdx == -1 && (k == "assignment" || k == "assignment address" || k == "hex") {
			assignIdx = i
		}
		if orgIdx == -1 && strings.HasPrefix(k, "organization") {
			orgIdx = i
		}
	}
	if assignIdx == -1 {
		assignIdx = 0
	}
	if orgIdx == -1 {
		orgIdx = 1
	}

	rows := 0
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read row: %w", err)
		}
		if len(rec) <= assignIdx || len(rec) <= orgIdx {
			continue
		}

		rawAssign := strings.TrimSpace(rec[assignIdx])
		org := strings.TrimSpace(rec[orgIdx])
		if rawAssign == "" || org == "" {
			continue
		}

		// Normalize: keep only first 6 hex, uppercase, strip separators
		oui := normalizeOUI(rawAssign)
		if len(oui) != 6 {
			continue
		}

		if err := w.Write([]string{oui, org}); err != nil {
			return fmt.Errorf("write row: %w", err)
		}
		rows++
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("flush csv: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("fsync tmp: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}

	// Atomic replace
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("replace %s: %w", destPath, err)
	}

	// If our lookup path matches destPath, hot-reload the in-memory DB
	if same, _ := filepath.Abs(destPath); same != "" {
		cfg, _ := filepath.Abs(ouiCSVPath)
		if cfg == same {
			if err := ReloadVendorDB(); err != nil {
				// Non-fatal: the file is updated; memory cache will reload on next process start
				fmt.Fprintf(os.Stderr, "Warning: failed to hot-reload OUI DB: %v\n", err)
			}
		}
	}

	return nil
}

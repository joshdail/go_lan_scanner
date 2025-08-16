package scanner

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	vendorDB   map[string]string
	vendorOnce sync.Once
	vendorMu   sync.RWMutex
	ouiCSVPath = "data/oui.csv" // default; override via SetOUIPath if needed
)

// SetOUIPath lets callers override where the CSV is located
func SetOUIPath(path string) {
	ouiCSVPath = path
}

// normalizeOUI takes a string like "DC-4B-A1" or "dc:4b:a1" or "dc4ba1"
// and returns "DC4BA1".
func normalizeOUI(s string) string {
	u := strings.ToUpper(s)
	u = strings.ReplaceAll(u, "-", "")
	u = strings.ReplaceAll(u, ":", "")
	u = strings.ReplaceAll(u, ".", "")
	if len(u) >= 6 {
		return u[:6]
	}
	return u
}

// loadVendorDBLocked reads CSV at path and replaces vendorDB atomically.
// Supports:
//   - Raw IEEE format: Assignment,Organization Name
//   - Sanitized format: OUI,OrganizationName
//   - New IEEE format: Registry,Assignment,Organization Name,Organization Address
func loadVendorDBLocked(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open OUI db: %w (at %s)", err, path)
	}
	defer f.Close()

	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("read CSV header: %w", err)
	}

	// Lowercase headers for comparison
	for i := range header {
		header[i] = strings.ToLower(strings.TrimSpace(header[i]))
	}

	isSanitized := (len(header) >= 2 && header[0] == "oui" && (header[1] == "organizationname" || header[1] == "organization"))
	isRaw := (len(header) >= 2 && header[0] == "assignment" && strings.HasPrefix(header[1], "organization"))
	isNewIEEE := (len(header) >= 3 && header[0] == "registry" && header[1] == "assignment" && strings.HasPrefix(header[2], "organization"))

	tmp := make(map[string]string)
	row := 1

	for {
		row++
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("csv read error on row %d: %w", row, err)
		}

		var key, org string
		switch {
		case isSanitized:
			if len(rec) >= 2 {
				key = normalizeOUI(rec[0])
				org = strings.TrimSpace(rec[1])
			}
		case isRaw:
			if len(rec) >= 2 {
				key = normalizeOUI(rec[0])
				org = strings.TrimSpace(rec[1])
			}
		case isNewIEEE:
			if len(rec) >= 3 {
				key = normalizeOUI(rec[1]) // Assignment
				org = strings.TrimSpace(rec[2])
			}
		default:
			// Fallback: try first two fields
			if len(rec) >= 2 {
				key = normalizeOUI(rec[0])
				org = strings.TrimSpace(rec[1])
			}
		}

		if len(key) == 6 && org != "" {
			tmp[key] = org
		}
	}

	// Atomically replace the map
	vendorMu.Lock()
	defer vendorMu.Unlock()
	vendorDB = tmp
	return nil
}

// ensureVendorLoaded lazily loads the DB once.
func ensureVendorLoaded() {
	vendorOnce.Do(func() {
		if !filepath.IsAbs(ouiCSVPath) {
			_ = os.MkdirAll(filepath.Dir(ouiCSVPath), 0o755)
		}
		if err := loadVendorDBLocked(ouiCSVPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load OUI DB: %v\n", err)
			vendorDB = make(map[string]string) // safe empty fallback
		}
	})
}

// ReloadVendorDB forces a reload (use after updating the CSV on disk).
func ReloadVendorDB() error {
	return loadVendorDBLocked(ouiCSVPath)
}

// lookupVendor resolves a MAC address (any separator) to a vendor name.
func lookupVendor(mac string) string {
	ensureVendorLoaded()

	norm := normalizeOUI(mac)
	if len(norm) < 6 {
		return "Unknown Vendor"
	}
	oui := norm[:6]

	vendorMu.RLock()
	vendor, ok := vendorDB[oui]
	vendorMu.RUnlock()

	if ok && vendor != "" {
		return vendor
	}
	return "Unknown Vendor"
}

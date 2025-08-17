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
	ouiCSVPath = "data/oui.csv"
)

// Override CSV filepath if needed
func SetOUIPath(path string) {
	ouiCSVPath = path
}

// Normalize MAC address
// Example:"DC-4B-A1" or "dc:4b:a1" or "dc4ba1" returns "DC4BA1".
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

// Check header row, determine format, and return string identifier
func determineCSVFormat(header []string) string {
	if len(header) < 2 {
		return "fallback"
	}
	h0 := strings.ToLower(strings.TrimSpace(header[0]))
	h1 := strings.ToLower(strings.TrimSpace(header[1]))

	if len(header) >= 3 && strings.ToLower(strings.TrimSpace(header[0])) == "registry" &&
		strings.ToLower(strings.TrimSpace(header[1])) == "assignment" {
		return "newIEEE"
	} else if h0 == "oui" && (h1 == "organizationname" || h1 == "organization") {
		return "sanitized"
	} else if h0 == "assignment" && strings.HasPrefix(h1, "organization") {
		return "raw"
	}
	return "fallback"
} // determineCSVFormat

// Return key (OUI) and organization name based on CSV format
func parseRecord(rec []string, format string) (string, string) {
	switch format {
	case "sanitized", "raw", "fallback":
		if len(rec) >= 2 {
			return normalizeOUI(rec[0]), strings.TrimSpace(rec[1])
		}
	case "newIEEE":
		if len(rec) >= 3 {
			return normalizeOUI(rec[1]), strings.TrimSpace(rec[2])
		}
	} // switch
	return "", ""
} // parseRecord

// Read CSV at path and replace vendorDB atomically
func loadVendorDBLocked(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open OUI db: %w (at %s)", err, path)
	}
	defer file.Close()

	r := csv.NewReader(file)
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("read CSV header: %w", err)
	}

	format := determineCSVFormat(header)
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
		key, org := parseRecord(rec, format)
		if len(key) == 6 && org != "" {
			tmp[key] = org
		}
	} // for
	vendorMu.Lock()
	defer vendorMu.Unlock()
	vendorDB = tmp
	return nil
} // loadVendorDBLocked

func ensureVendorLoaded() {
	vendorOnce.Do(func() {
		if !filepath.IsAbs(ouiCSVPath) {
			_ = os.MkdirAll(filepath.Dir(ouiCSVPath), 0o755)
		}
		if err := loadVendorDBLocked(ouiCSVPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load OUI database: %v\n", err)
			vendorDB = make(map[string]string)
		}
	})
} // ensureVendorLoaded

func ReloadVendorDB() error {
	return loadVendorDBLocked(ouiCSVPath)
}

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
} // lookupVendor

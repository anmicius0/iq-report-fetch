// internal/report/csvreport.go
package report

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/rs/zerolog"
)

// Row represents a single policy violation row for CSV output.
// Row represents a single policy violation row written to CSV.
// It is intentionally small and focuses on the fields required for output.
type Row struct {
	Application    string
	Organization   string
	Policy         string
	Format         string
	Component      string
	Threat         int
	PolicyAction   string
	ConstraintName string
	Condition      string
	CVE            string
}

// csvHeaders returns the CSV header row in the required order.
// csvHeaders returns the column headers for CSV output. It is internal
// as the CSV layout is an implementation detail of this package.
func csvHeaders() []string {
	return []string{
		"No.",
		"Application",
		"Organization",
		"Policy",
		"Format",
		"Component",
		"Threat",
		"Policy/Action",
		"Constraint Name",
		"Condition",
		"CVE",
	}
}

// WriteCSV writes the given rows into a CSV file at destPath. It ensures
// the destination directory exists and writes to a temporary file in the
// same directory before renaming it to the final destination. Errors are
// returned to the caller; this function does not log errors itself.
func WriteCSV(destPath string, rows []Row, logger zerolog.Logger) error {
	// Ensure absolute path with proper separators for Windows compatibility
	absPath, err := filepath.Abs(destPath)
	if err != nil {
		return fmt.Errorf("get absolute path: %w", err)
	}

	dir := filepath.Dir(absPath)
	logger.Debug().Str("dir", dir).Msg("preparing output directory")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.Error().Err(err).Str("dir", dir).Msg("failed to create output dir")
		return fmt.Errorf("prepare output dir: %w", err)
	}

	// Create temp file in SAME directory as final file to ensure os.Rename works on Windows
	tmp, err := os.CreateTemp(dir, ".tmp-*.csv")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	// Ensure the temporary file is closed and removed when we return.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	logger.Debug().Str("tmp", tmpPath).Msg("created temp file")

	w := csv.NewWriter(tmp)

	// header
	if err := w.Write(csvHeaders()); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// rows
	for i, r := range rows {
		record := []string{
			strconv.Itoa(i + 1),
			r.Application,
			r.Organization,
			r.Policy,
			r.Format,
			r.Component,
			strconv.Itoa(r.Threat),
			r.PolicyAction,
			r.ConstraintName,
			r.Condition,
			r.CVE,
		}
		if err := w.Write(record); err != nil {
			return fmt.Errorf("write row %d: %w", i+1, err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("flush csv: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("fsync temp: %w", err)
	}

	// Close temp file BEFORE rename (Windows requires file to be closed)
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	// Remove existing destination file if it exists (Windows requirement)
	_ = os.Remove(absPath)

	// Atomic rename (now works on Windows since both files are in same directory)
	if err := os.Rename(tmpPath, absPath); err != nil {
		return fmt.Errorf("atomic rename: %w", err)
	}

	if err := os.Chmod(absPath, 0o644); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	logger.Info().Str("path", absPath).Int("rows", len(rows)).Msg("csv file written successfully")
	return nil
}

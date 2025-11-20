// internal/services/iqreport.go
package services

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/anmicius0/iqserver-report-fetch-go/internal/client"
	"github.com/anmicius0/iqserver-report-fetch-go/internal/config"
	"github.com/anmicius0/iqserver-report-fetch-go/internal/report"
	"github.com/rs/zerolog"
)

// IQReportService orchestrates fetching IQ Server data and exporting CSV reports.
// It uses an injected client to make requests and a logger for high-level
// informational output. Business logic is kept in this package while
// I/O and HTTP logic lives in the internal/report and internal/client
// packages respectively.
type IQReportService struct {
	cfg    *config.Config
	client *client.Client
	logger zerolog.Logger
}

// AppReportResult holds the violation rows and any error encountered
// while processing a single application concurrently.
// AppReportResult carries the rows produced for a single application and
// any error that occurred while collecting them. Errors are returned to the
// caller rather than being logged here.
type AppReportResult struct {
	Rows []report.Row
	Err  error
}

// NewIQReportService constructs a new service.
// NewIQReportService creates a new IQReportService configured with cfg and
// a client used to talk to IQ Server.
func NewIQReportService(cfg *config.Config, cl *client.Client, logger zerolog.Logger) *IQReportService {
	return &IQReportService{cfg: cfg, client: cl, logger: logger}
}

// GenerateLatestPolicyReport fetches latest policy violations for all applications
// and writes a CSV to cfg.OutputDir/filename, returning the absolute file path.
func (s *IQReportService) GenerateLatestPolicyReport(ctx context.Context, filename string) (string, error) {
	logger := s.logger.With().Str("filename", filename).Logger()

	logger.Info().Msg("GenerateLatestPolicyReport invoked")

	// =================================================================
	// 1. APPLICATION AND ORGANIZATION FETCHING (Sequential Setup)
	// =================================================================

	// Fetch application list
	apps, err := s.client.GetApplications(ctx)
	if err != nil {
		return "", fmt.Errorf("get applications: %w", err)
	}
	logger.Info().Int("count", len(apps)).Msg("Fetched applications")

	if len(apps) == 0 {
		logger.Warn().Msg("Task finished: no applications found matching criteria")
		return "", fmt.Errorf("no applications found")
	}

	// Fetch organizations to create an ID-to-name map
	orgs, err := s.client.GetOrganizations(ctx)
	if err != nil {
		return "", fmt.Errorf("get organizations: %w", err)
	}
	orgIDToName := make(map[string]string)
	for _, org := range orgs {
		orgIDToName[org.ID] = org.Name
	}
	logger.Info().Int("count", len(orgIDToName)).Msg("Created organization ID-to-name map")

	// =================================================================
	// 2. PROCESS APPLICATIONS CONCURRENTLY
	// =================================================================

	// Setup concurrency primitives: semaphore (max 10), channel for results, WaitGroup
	sem := make(chan struct{}, 10) // Bounded semaphore: max 10 concurrent
	resultsChan := make(chan AppReportResult, len(apps))
	var wg sync.WaitGroup

	s.logger.Info().Int("appsToProcess", len(apps)).Int("maxConcurrent", 10).Msg("Starting concurrent report fetching for applications")

	// Launch a goroutine for each application
	for _, a := range apps {
		wg.Add(1)

		// Capture loop variable 'a' for use in the goroutine closure
		app := a

		go func() {
			defer wg.Done()

			// Acquire semaphore with context cancellation support
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }() // Release semaphore
			case <-ctx.Done():
				return
			}

			// Check for context cancellation/timeout early
			if ctx.Err() != nil {
				return
			}

			appLogger := s.logger.With().Str("appPublicID", app.PublicID).Str("appInternalID", app.ID).Logger()

			// 2a. Fetch latest report info
			reportInfo, err := s.client.GetLatestReportInfo(ctx, app.ID)
			if err != nil {
				// Return error to caller (collected by the aggregator)
				select {
				case resultsChan <- AppReportResult{Err: fmt.Errorf("app %s: %w", app.ID, err)}:
				case <-ctx.Done():
				}
				return
			}

			// Skip if no report available
			if reportInfo == nil || strings.TrimSpace(reportInfo.ReportHTMLURL) == "" {
				// No report found: return empty rows without error
				select {
				case resultsChan <- AppReportResult{Rows: nil}:
				case <-ctx.Done():
				}
				return
			}

			// 2b. Extract report ID and validate
			_, reportID, found := strings.Cut(reportInfo.ReportHTMLURL, "/report/")
			if !found || reportID == "" {
				select {
				case resultsChan <- AppReportResult{Err: fmt.Errorf("app %s: malformed report URL: %s", app.ID, reportInfo.ReportHTMLURL)}:
				case <-ctx.Done():
				}
				return
			}
			appLogger.Debug().Str("reportID", reportID).Str("stage", reportInfo.Stage).Msg("Parsed report ID")

			// 2c. Look up organization name
			orgName, ok := orgIDToName[app.OrganizationID]
			if !ok {
				orgName = app.OrganizationID
				// fallback to ID
				appLogger.Debug().Str("orgID", app.OrganizationID).Msg("organization name not found, using ID as fallback")
			}

			// 2d. Fetch policy violations (returns []report.Row)
			clientRows, err := s.client.GetPolicyViolations(ctx, app.PublicID, reportID, orgName)
			if err != nil {
				select {
				case resultsChan <- AppReportResult{Err: fmt.Errorf("app %s: get policy violations: %w", app.ID, err)}:
				case <-ctx.Done():
				}
				return
			}
			appLogger.Debug().Int("rowsCount", len(clientRows)).Msg("Fetched policy violations")

			// 2f. Send successful results to the channel
			select {
			case resultsChan <- AppReportResult{Rows: clientRows}:
			case <-ctx.Done():
			}
		}()
	}

	// Wait for all goroutines to finish, then close the channel in a non-blocking way
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Aggregate results
	var allViolationRows []report.Row

	// Aggregate results and collect any errors
	var errs []error
	for res := range resultsChan {
		if res.Err != nil {
			errs = append(errs, res.Err)
			continue
		}
		allViolationRows = append(allViolationRows, res.Rows...)
	}

	// =================================================================
	// 3. CSV GENERATION AND FINAL PATH RETURN
	// =================================================================

	target := filepath.Join(s.cfg.OutputDir, filename)
	s.logger.Info().Str("path", target).Int("totalRows", len(allViolationRows)).Msg("Writing CSV report")

	if err := report.WriteCSV(target, allViolationRows, s.logger); err != nil {
		return "", fmt.Errorf("write csv: %w", err)
	}

	s.logger.Info().Str("path", target).Msg("Report written successfully")

	if len(errs) > 0 {
		return target, fmt.Errorf("encountered errors while fetching reports: %w", errors.Join(errs...))
	}

	return target, nil
}

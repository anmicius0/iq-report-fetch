// internal/client/client.go
package client

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/anmicius0/iqserver-report-fetch-go/internal/report"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
)

// Client is an HTTP client configured for communicating with IQ Server.
// It wraps an authenticated Resty client and a logger. Callers may use
// the methods on Client to fetch applications, organizations and reports.
type Client struct {
	baseURL    string
	logger     zerolog.Logger
	httpClient *resty.Client
}

// =================================================================
// IQ Server API Model Definitions (Input/Output)
// =================================================================

// Application represents a single application returned by IQ Server.
// Application describes a single IQ Server application record returned by the API.
type Application struct {
	ID             string `json:"id"`
	PublicID       string `json:"publicId"`
	OrganizationID string `json:"organizationId"`
}

type applicationsEnvelope struct {
	Applications []Application `json:"applications"`
}

// Organization represents a simplified IQ Server organization record.
// Organization describes a simple IQ Server organization record.
type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type organizationsEnvelope struct {
	Organizations []Organization `json:"organizations"`
}

// ReportInfo contains metadata about an application's latest report.
// ReportInfo describes metadata for a report (most recent report for an application).
type ReportInfo struct {
	Stage         string `json:"stage"`
	ReportHTMLURL string `json:"reportHtmlUrl"`
}

// =================================================================
// Policy Violation Report Structure (Complex API Response)
// =================================================================

// Condition is the lowest level detail within a constraint.
type Condition struct {
	ConditionSummary string `json:"conditionSummary"`
}

// Constraint is a group of conditions within a policy violation.
type Constraint struct {
	ConstraintName string      `json:"constraintName"`
	Conditions     []Condition `json:"conditions"`
}

// Violation details a specific policy break for a component.
type Violation struct {
	PolicyName        string       `json:"policyName"`
	PolicyThreatLevel float64      `json:"policyThreatLevel"` // IQ Server returns numeric fields as float64
	Constraints       []Constraint `json:"constraints"`
}

type ComponentIdentifier struct {
	Format string `json:"format"`
}

// Component is a library/asset with associated violations.
type Component struct {
	DisplayName         string      `json:"displayName"`
	Violations          []Violation `json:"violations"`
	ComponentIdentifier `json:"componentIdentifier"`
}

// PolicyViolationReport is the top-level structure for the policy violations report API.
type PolicyViolationReport struct {
	Components []Component `json:"components"`
}

// =================================================================
// Client Initialization
// =================================================================

// NewClient creates a new Client configured with credentials and base URL.
// The provided logger is used for informational and debug output only.
func NewClient(serverURL, username, password string, logger zerolog.Logger) (*Client, error) {
	// Defense checks
	if strings.TrimSpace(serverURL) == "" {
		return nil, fmt.Errorf("serverURL is required")
	}
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if password == "" {
		return nil, fmt.Errorf("password is required")
	}
	// The logger is a struct, so it cannot be nil. No check needed.

	// Expect serverURL to already include /api/v2
	baseURL := strings.TrimSuffix(serverURL, "/")
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid baseURL: %w", err)
	}
	u.Path = path.Clean(u.Path)
	baseURL = u.String()
	baseURL = strings.TrimRight(baseURL, "/") + "/"

	r := resty.New().
		SetBaseURL(baseURL).
		SetBasicAuth(username, password).
		SetHeader("Accept", "application/json").
		SetTimeout(30 * time.Second)

	// Resty hooks for logging
	r.OnBeforeRequest(func(c *resty.Client, req *resty.Request) error {
		logger.Debug().
			Str("method", req.Method).
			Str("url", req.URL).
			Str("query", req.QueryParam.Encode()).
			Msg("Executing request")
		return nil
	})
	r.OnAfterResponse(func(c *resty.Client, resp *resty.Response) error {
		logger.Debug().
			Int("status", resp.StatusCode()).
			Str("url", resp.Request.URL).
			Str("method", resp.Request.Method).
			Msg("Request completed")
		return nil
	})

	cl := &Client{
		baseURL:    baseURL,
		logger:     logger,
		httpClient: r,
	}
	logger.Info().Str("baseURL", baseURL).Msg("Initialized IQServer API client")
	return cl, nil
}

// =================================================================
// Public Client Methods
// =================================================================

// GetApplications fetches a list of applications from the IQ Server.
func (c *Client) GetApplications(ctx context.Context) ([]Application, error) {
	endpoint := "applications"
	logger := c.logger.With().Str("orgId", "all").Logger()
	logger.Debug().Msg("Fetching applications")

	var env applicationsEnvelope
	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetResult(&env).
		SetError(&map[string]any{}).
		Get(endpoint)
	if err != nil {
		return nil, err
	}

	c.logger.Debug().Int("status", resp.StatusCode()).Str("body", resp.String()).Msg("raw response")
	if resp.IsError() {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode(), resp.String())
	}

	return env.Applications, nil
}

// GetLatestReportInfo fetches the metadata for the most recent report for a given internal application ID.
func (c *Client) GetLatestReportInfo(ctx context.Context, appID string) (*ReportInfo, error) {
	endpoint := fmt.Sprintf("reports/applications/%s", appID)
	var reports []ReportInfo

	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetResult(&reports).
		Get(endpoint)
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode(), resp.Status())
	}

	if len(reports) > 0 {
		c.logger.Debug().Int("count", len(reports)).Str("appId", appID).Msg("Found reports")
		r := reports[0]
		return &r, nil
	}

	c.logger.Debug().Str("appId", appID).Msg("No reports found")
	return nil, nil
}

// GetPolicyViolations fetches the detailed policy violation report for a specific application and report ID.
func (c *Client) GetPolicyViolations(ctx context.Context, publicID, reportID, orgName string) ([]report.Row, error) {
	c.logger.Debug().Str("publicId", publicID).Str("reportId", reportID).Msg("Fetching policy violations")

	endpoint := fmt.Sprintf("applications/%s/reports/%s/policy", publicID, reportID)
	params := url.Values{"includeViolationTimes": []string{"true"}}

	var report PolicyViolationReport // Use the explicit struct
	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetQueryParamsFromValues(params).
		SetResult(&report). // Unmarshal directly into struct
		Get(endpoint)
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode(), resp.Status())
	}

	// Parse and filter to report rows using the structured data
	return parseReportRows(report, publicID, orgName), nil
}

// GetOrganizations fetches the list of all organizations.
func (c *Client) GetOrganizations(ctx context.Context) ([]Organization, error) {
	c.logger.Debug().Msg("Fetching organizations")

	var env organizationsEnvelope
	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetResult(&env).
		Get("organizations")
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode(), resp.String())
	}

	c.logger.Debug().Int("count", len(env.Organizations)).Msg("Retrieved organizations")
	return env.Organizations, nil
}

// =================================================================
// Helper Functions
// =================================================================

// parseReportRows converts the structured API response into flat report.Row slice.
func parseReportRows(rawReport PolicyViolationReport, appPublicID string, orgName string) []report.Row {
	var rows []report.Row

	for _, comp := range rawReport.Components {
		compName := comp.DisplayName
		format := comp.ComponentIdentifier.Format
		for _, v := range comp.Violations {
			policyName := v.PolicyName
			// Threat level comes as float64, cast to int
			threat := int(v.PolicyThreatLevel)
			policyAction := fmt.Sprintf("Security-%d", threat)
			for _, constr := range v.Constraints {
				constraintName := constr.ConstraintName
				var condSummaries []string
				for _, cond := range constr.Conditions {
					condSummaries = append(condSummaries, cond.ConditionSummary)
				}
				rows = append(rows, report.Row{
					Application:    appPublicID,
					Organization:   orgName,
					Policy:         policyName,
					Format:         format,
					Component:      compName,
					Threat:         threat,
					PolicyAction:   policyAction,
					ConstraintName: constraintName,
					Condition:      strings.Join(condSummaries, " | "),
					CVE:            "",
				})
			}
		}
	}
	return rows
}

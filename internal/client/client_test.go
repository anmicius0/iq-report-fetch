// internal/client/client_test.go
package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func newTestLogger() zerolog.Logger {
	return zerolog.New(io.Discard)
}

func TestClient_EndToEndAgainstStub(t *testing.T) {
	mux := http.NewServeMux()

	// Register a subtree handler to avoid trailing-slash and exact-match pitfalls.
	mux.HandleFunc("/api/v2/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/applications":
			resp := map[string]any{
				"applications": []map[string]any{
					{
						"id":             "app-internal-1",
						"publicId":       "app-public-1",
						"organizationId": "org-1",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		case "/api/v2/reports/applications/app-internal-1":
			resp := []map[string]any{
				{
					"stage":         "build",
					"reportHtmlUrl": "https://stub/report/rpt-1",
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		case "/api/v2/applications/app-public-1/reports/rpt-1/policy":
			resp := map[string]any{
				"components": []any{
					map[string]any{
						"displayName": "setuptools 80.9.0 (.tar.gz)",
						"componentIdentifier": map[string]any{
							"format": "pypi",
						},
						"violations": []any{
							map[string]any{
								"policyName":        "Security-Medium",
								"policyThreatLevel": 7,
								"constraints": []any{
									map[string]any{
										"constraintName": "Medium risk CVSS score",
										"conditions": []any{
											map[string]any{"conditionSummary": "Security Vulnerability Severity >= 4"},
											map[string]any{"conditionSummary": "Security Vulnerability Severity < 7"},
										},
									},
								},
							},
						},
					},
					map[string]any{
						"displayName": "setuptools (py3-none-any) 80.9.0 (.whl)",
						"componentIdentifier": map[string]any{
							"format": "pypi",
						},
						"violations": []any{
							map[string]any{
								"policyName":        "Security-Medium",
								"policyThreatLevel": 7,
								"constraints": []any{
									map[string]any{
										"constraintName": "Medium risk CVSS score",
										"conditions": []any{
											map[string]any{"conditionSummary": "Security Vulnerability Severity >= 4"},
											map[string]any{"conditionSummary": "Security Vulnerability Severity < 7"},
										},
									},
								},
							},
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		case "/api/v2/organizations":
			resp := map[string]any{
				"organizations": []map[string]any{
					{"id": "org-1", "name": "personal"},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		default:
			http.NotFound(w, r)
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	baseURL := strings.TrimRight(srv.URL, "/") + "/api/v2"
	iqClient, err := NewClient(baseURL, "u", "p", newTestLogger())
	if err != nil {
		t.Fatalf("NewClient error = %v", err)
	}

	// GetApplications all
	apps, err := iqClient.GetApplications(rCtx(t))
	if err != nil {
		t.Fatalf("GetApplications error = %v", err)
	}
	if len(apps) != 1 || !strings.EqualFold(apps[0].PublicID, "app-public-1") {
		t.Fatalf("unexpected apps: %#v", apps)
	}

	// Latest report
	reportInfo, err := iqClient.GetLatestReportInfo(rCtx(t), "app-internal-1")
	if err != nil || reportInfo == nil {
		t.Fatalf("GetLatestReportInfo error = %v ri=%v", err, reportInfo)
	}
	if !strings.Contains(reportInfo.ReportHTMLURL, "/report/rpt-1") {
		t.Errorf("ReportHTMLURL = %q", reportInfo.ReportHTMLURL)
	}

	// Policy violations
	violationRows, err := iqClient.GetPolicyViolations(rCtx(t), "app-public-1", "rpt-1", "personal")
	if err != nil {
		t.Fatalf("GetPolicyViolations error = %v", err)
	}
	if len(violationRows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(violationRows))
	}
	if violationRows[0].Threat != 7 || violationRows[0].PolicyAction != "Security-7" {
		t.Errorf("row mapping unexpected: %#v", violationRows[0])
	}
	if violationRows[0].Format != "pypi" {
		t.Errorf("expected format 'pypi', got %q", violationRows[0].Format)
	}
	if violationRows[1].Format != "pypi" {
		t.Errorf("expected format 'pypi', got %q", violationRows[1].Format)
	}

	// Orgs
	orgs, err := iqClient.GetOrganizations(rCtx(t))
	if err != nil || len(orgs) != 1 {
		t.Fatalf("GetOrganizations error=%v orgs=%v", err, orgs)
	}
}

func TestNewClient_Validation(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		user     string
		pass     string
		wantErr  bool
		errMatch string
	}{
		{"Valid", "http://localhost", "u", "p", false, ""},
		{"MissingURL", "", "u", "p", true, "serverURL is required"},
		{"MissingUser", "http://localhost", "", "p", true, "username is required"},
		{"MissingPass", "http://localhost", "u", "", true, "password is required"},
		{"InvalidURL", "://invalid", "u", "p", true, "invalid baseURL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(tt.url, tt.user, tt.pass, newTestLogger())
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errMatch) {
				t.Errorf("NewClient() error = %v, want match %q", err, tt.errMatch)
			}
		})
	}
}

func TestClient_GetApplications_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	c, _ := NewClient(server.URL+"/api/v2", "u", "p", newTestLogger())
	_, err := c.GetApplications(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected HTTP 500 error, got %v", err)
	}
}

func TestClient_GetLatestReportInfo_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]")) // Empty array
	}))
	defer server.Close()

	c, _ := NewClient(server.URL+"/api/v2", "u", "p", newTestLogger())
	info, err := c.GetLatestReportInfo(context.Background(), "app-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info != nil {
		t.Errorf("expected nil info, got %v", info)
	}
}

func TestClient_GetOrganizations_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	c, _ := NewClient(server.URL+"/api/v2", "u", "p", newTestLogger())
	_, err := c.GetOrganizations(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("expected HTTP 403 error, got %v", err)
	}
}

// rCtx returns a cancellable context with a small timeout and ensures cancel via t.Cleanup.
func rCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}

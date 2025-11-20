// internal/config/config.go
package config

import (
	"strings"

	"github.com/caarlos0/env/v11"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
)

// Config holds environment-driven configuration for the application.
// Fields are populated from environment variables and may have sensible
// defaults applied in Load.
type Config struct {
	// IQ Server config
	IQServerURL string `env:"IQ_SERVER_URL,required" validate:"required,url"`
	IQUsername  string `env:"IQ_USERNAME,required" validate:"required"`
	IQPassword  string `env:"IQ_PASSWORD,required" validate:"required"`

	// IO config
	// Report output directory. Can be set via REPORT_OUTPUT_DIR, defaults to "reports_output" when empty.
	OutputDir string `env:"REPORT_OUTPUT_DIR" validate:"required"`
}

// Load reads environment variables (and optional config/.env file) and
// returns a validated Config populated with sensible defaults when needed.
func Load() (*Config, error) {
	// Load .env if present; ignore missing file errors to allow env-driven usage.
	_ = godotenv.Load("config/.env")

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}

	// Default output directory when not provided via env
	if strings.TrimSpace(cfg.OutputDir) == "" {
		cfg.OutputDir = "reports_output"
	}

	// Validate the config once defaults are applied
	validate := validator.New()
	if err := validate.Struct(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

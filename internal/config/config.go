// Package config provides configuration loading and defaults for the
// SCADA Exposure Discovery and Vulnerability Detection Platform.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure for the platform.
type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Database       DatabaseConfig       `yaml:"database"`
	Scanner        ScannerConfig        `yaml:"scanner"`
	Shodan         ShodanConfig         `yaml:"shodan"`
	DNS            DNSConfig            `yaml:"dns"`
	Crawl          CrawlConfig          `yaml:"crawl"`
	SecurityTrails SecurityTrailsConfig `yaml:"security_trails"`
	Censys         CensysConfig         `yaml:"censys"`
}

// CensysConfig holds Censys API credentials.
type CensysConfig struct {
	APIID     string `yaml:"api_id"`
	APISecret string `yaml:"api_secret"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	DSN string `yaml:"dsn"`
}

// ScannerConfig holds port scanning and concurrency settings.
type ScannerConfig struct {
	// SCADAPorts is the list of TCP ports to scan by default.
	// Covers: S7 (102), Modbus (502), DNP3 (20000), EtherNet/IP (44818),
	//         BACnet (47808), OPC-UA (4840), Fox/Niagara (1911, 4911),
	//         Omron FINS (9600), IEC 60870-5-104 (2404), Crimson (4000),
	//         ProConOS (20547), Mitsubishi MELSEC (38400).
	SCADAPorts []int `yaml:"scada_ports"`

	// TimeoutMS is the per-connection timeout in milliseconds.
	TimeoutMS int `yaml:"timeout_ms"`

	// Concurrency is the number of simultaneous scan workers.
	Concurrency int `yaml:"concurrency"`

	// RateLimitPerSec caps the number of new connections opened per second.
	RateLimitPerSec int `yaml:"rate_limit_per_sec"`

	// DefaultProfile controls scan depth. Valid values: light, standard, deep.
	DefaultProfile string `yaml:"default_profile"`
}

// ShodanConfig holds Shodan API credentials.
type ShodanConfig struct {
	APIKey string `yaml:"api_key"`
}

// SecurityTrailsConfig holds SecurityTrails API credentials.
type SecurityTrailsConfig struct {
	APIKey string `yaml:"api_key"`
}

// DNSConfig holds DNS resolver settings.
type DNSConfig struct {
	// Resolvers is the list of DNS resolver addresses (host:port).
	Resolvers []string `yaml:"resolvers"`
}

// CrawlConfig holds web-crawling settings.
type CrawlConfig struct {
	// Depth is the maximum link-follow depth during HTTP crawling.
	Depth int `yaml:"depth"`
}

// Defaults returns a Config populated with sensible production defaults.
func Defaults() Config {
	return Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		Database: DatabaseConfig{
			DSN: "postgres://otnation:otnation@localhost:5432/otnation?sslmode=disable",
		},
		Scanner: ScannerConfig{
			SCADAPorts: []int{
				102,   // Siemens S7 / ISO-TSAP
				502,   // Modbus TCP
				20000, // DNP3
				44818, // EtherNet/IP
				47808, // BACnet/IP
				4840,  // OPC-UA
				1911,  // Niagara Fox
				9600,  // Omron FINS
				2404,  // IEC 60870-5-104
				4000,  // Crimson v3
				20547, // ProConOS
				38400, // Mitsubishi MELSEC-Q
			},
			TimeoutMS:       3000,
			Concurrency:     50,
			RateLimitPerSec: 100,
			DefaultProfile:  "standard",
		},
		Shodan: ShodanConfig{
			APIKey: "",
		},
		DNS: DNSConfig{
			Resolvers: []string{
				"8.8.8.8:53",
				"1.1.1.1:53",
				"9.9.9.9:53",
			},
		},
		Crawl: CrawlConfig{
			Depth: 2,
		},
	}
}

// LoadFromFile reads a YAML configuration file at the given path and merges
// its values on top of the defaults.  Missing keys retain their default values.
func LoadFromFile(path string) (Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("config: reading file %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("config: parsing YAML in %q: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return cfg, fmt.Errorf("config: validation failed: %w", err)
	}

	return cfg, nil
}

// validate performs basic sanity checks on the loaded configuration.
func (c *Config) validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port %d is out of range [1, 65535]", c.Server.Port)
	}
	if c.Database.DSN == "" {
		return fmt.Errorf("database.dsn must not be empty")
	}
	if c.Scanner.Concurrency < 1 {
		return fmt.Errorf("scanner.concurrency must be at least 1")
	}
	profile := c.Scanner.DefaultProfile
	if profile != "light" && profile != "standard" && profile != "deep" {
		return fmt.Errorf("scanner.default_profile must be one of: light, standard, deep")
	}
	return nil
}

// Addr returns the formatted listen address (host:port).
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

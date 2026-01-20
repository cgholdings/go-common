package encryption

import (
	"fmt"
	"os"
)

// Config holds the configuration for the encryption plugin
type Config struct {
	// Key is the encryption key (16, 24, or 32 bytes)
	Key []byte
	// KeyString is the base64-encoded encryption key (alternative to Key)
	KeyString string
	// KeyEnvVar is the environment variable name containing the encryption key
	KeyEnvVar string
}

// NewEncryptorFromConfig creates a new Encryptor from a Config
func NewEncryptorFromConfig(config *Config) (*Encryptor, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	// Priority: Key > KeyString > KeyEnvVar
	if len(config.Key) > 0 {
		return NewEncryptor(config.Key)
	}

	if config.KeyString != "" {
		return NewEncryptorFromString(config.KeyString)
	}

	if config.KeyEnvVar != "" {
		keyString := os.Getenv(config.KeyEnvVar)
		if keyString == "" {
			return nil, fmt.Errorf("environment variable %s is not set or empty", config.KeyEnvVar)
		}
		return NewEncryptorFromString(keyString)
	}

	return nil, fmt.Errorf("no encryption key provided in config (Key, KeyString, or KeyEnvVar required)")
}

// NewPluginFromConfig creates a new encryption plugin from a Config
func NewPluginFromConfig(config *Config) (*Plugin, error) {
	encryptor, err := NewEncryptorFromConfig(config)
	if err != nil {
		return nil, err
	}

	return NewPlugin(encryptor), nil
}

// DefaultConfig returns a default configuration that reads the key from the
// ENCRYPTION_KEY environment variable
func DefaultConfig() *Config {
	return &Config{
		KeyEnvVar: "ENCRYPTION_KEY",
	}
}

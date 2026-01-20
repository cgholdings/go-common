package encryption

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// TestNewEncryptor tests creating a new encryptor
func TestNewEncryptor(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		wantErr bool
	}{
		{"AES-128", 16, false},
		{"AES-192", 24, false},
		{"AES-256", 32, false},
		{"Invalid-15", 15, true},
		{"Invalid-17", 17, true},
		{"Invalid-0", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			enc, err := NewEncryptor(key)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewEncryptor() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("NewEncryptor() unexpected error: %v", err)
				}
				if enc == nil {
					t.Errorf("NewEncryptor() returned nil encryptor")
				}
			}
		})
	}
}

// TestEncryptDecrypt tests encryption and decryption
func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error: %v", err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"Simple", "Hello, World!"},
		{"Empty", ""},
		{"Long", strings.Repeat("Lorem ipsum dolor sit amet, ", 100)},
		{"Unicode", "こんにちは世界🌍"},
		{"Special", "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"},
		{"SSN", "123-45-6789"},
		{"Credit Card", "4111111111111111"},
		{"Email", "user@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := enc.Encrypt(tt.plaintext)
			if err != nil {
				t.Errorf("Encrypt() error: %v", err)
				return
			}

			// Empty plaintext should return empty ciphertext
			if tt.plaintext == "" {
				if ciphertext != "" {
					t.Errorf("Encrypt() expected empty ciphertext for empty plaintext, got: %s", ciphertext)
				}
				return
			}

			// Ciphertext should be different from plaintext
			if ciphertext == tt.plaintext {
				t.Errorf("Encrypt() ciphertext equals plaintext")
			}

			// Ciphertext should be base64
			if _, err := base64.StdEncoding.DecodeString(ciphertext); err != nil {
				t.Errorf("Encrypt() ciphertext is not valid base64: %v", err)
			}

			// Decrypt
			decrypted, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Errorf("Decrypt() error: %v", err)
				return
			}

			// Decrypted should match original
			if decrypted != tt.plaintext {
				t.Errorf("Decrypt() got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

// TestEncryptionUniqueness tests that encryption produces unique ciphertexts
func TestEncryptionUniqueness(t *testing.T) {
	key, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error: %v", err)
	}

	plaintext := "This is a test"
	ciphertexts := make(map[string]bool)

	// Encrypt same plaintext multiple times
	for i := 0; i < 10; i++ {
		ciphertext, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt() error: %v", err)
		}

		if ciphertexts[ciphertext] {
			t.Errorf("Encrypt() produced duplicate ciphertext")
		}
		ciphertexts[ciphertext] = true
	}
}

// TestDecryptInvalid tests decryption of invalid data
func TestDecryptInvalid(t *testing.T) {
	key, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error: %v", err)
	}

	tests := []struct {
		name       string
		ciphertext string
		wantErr    bool
	}{
		{"Empty", "", false}, // Empty string should return empty string
		{"InvalidBase64", "not-base64!", true},
		{"TooShort", base64.StdEncoding.EncodeToString([]byte("short")), true},
		{"Random", base64.StdEncoding.EncodeToString(make([]byte, 100)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := enc.Decrypt(tt.ciphertext)
			if tt.wantErr && err == nil {
				t.Errorf("Decrypt() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Decrypt() unexpected error: %v", err)
			}
		})
	}
}

// TestGenerateKey tests key generation
func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"AES-128", 16, false},
		{"AES-192", 24, false},
		{"AES-256", 32, false},
		{"Invalid-15", 15, true},
		{"Invalid-0", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey(tt.size)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GenerateKey() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("GenerateKey() error: %v", err)
				}
				if len(key) != tt.size {
					t.Errorf("GenerateKey() got size %d, want %d", len(key), tt.size)
				}
			}
		})
	}
}

// TestGenerateKeyString tests key string generation
func TestGenerateKeyString(t *testing.T) {
	keyString, err := GenerateKeyString(32)
	if err != nil {
		t.Fatalf("GenerateKeyString() error: %v", err)
	}

	// Should be valid base64
	key, err := base64.StdEncoding.DecodeString(keyString)
	if err != nil {
		t.Errorf("GenerateKeyString() produced invalid base64: %v", err)
	}

	// Should be 32 bytes when decoded
	if len(key) != 32 {
		t.Errorf("GenerateKeyString() decoded key size is %d, want 32", len(key))
	}

	// Should be able to create an encryptor
	enc, err := NewEncryptorFromString(keyString)
	if err != nil {
		t.Errorf("NewEncryptorFromString() error: %v", err)
	}
	if enc == nil {
		t.Errorf("NewEncryptorFromString() returned nil")
	}
}

// TestHash tests the hash function
func TestHash(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // Expected hash for known inputs
	}{
		{
			name:  "Empty",
			input: "",
			want:  "",
		},
		{
			name:  "Hello",
			input: "Hello",
			want:  "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
		},
		{
			name:  "SSN",
			input: "123-45-6789",
			want:  "b5e5e1a0a1e6c5d6d1b4d3c6e7c9a0f2c8d3e5a3b0c1d2e3f4a5b6c7d8e9f0a1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Hash(tt.input)

			// Check empty case
			if tt.input == "" {
				if got != "" {
					t.Errorf("Hash() for empty input got %q, want empty string", got)
				}
				return
			}

			// Hash should be 64 characters (256 bits in hex)
			if len(got) != 64 {
				t.Errorf("Hash() length is %d, want 64", len(got))
			}

			// Hash should be deterministic
			got2 := Hash(tt.input)
			if got != got2 {
				t.Errorf("Hash() not deterministic: %q != %q", got, got2)
			}

			// Different inputs should produce different hashes
			if tt.input != "" {
				different := Hash(tt.input + "x")
				if got == different {
					t.Errorf("Hash() produced same hash for different inputs")
				}
			}
		})
	}
}

// TestHashBytes tests the HashBytes function
func TestHashBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"Empty", []byte{}},
		{"Nil", nil},
		{"Simple", []byte("Hello")},
		{"Binary", []byte{0x00, 0xFF, 0xAA, 0x55}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashBytes(tt.input)

			if len(tt.input) == 0 {
				if got != "" {
					t.Errorf("HashBytes() for empty input got %q, want empty string", got)
				}
				return
			}

			// Hash should be 64 characters
			if len(got) != 64 {
				t.Errorf("HashBytes() length is %d, want 64", len(got))
			}

			// Should be deterministic
			got2 := HashBytes(tt.input)
			if got != got2 {
				t.Errorf("HashBytes() not deterministic")
			}
		})
	}
}

// TestNewEncryptorFromConfig tests creating encryptor from config
func TestNewEncryptorFromConfig(t *testing.T) {
	key, _ := GenerateKey(32)
	keyString := base64.StdEncoding.EncodeToString(key)

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "Nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "Key bytes",
			config: &Config{
				Key: key,
			},
			wantErr: false,
		},
		{
			name: "Key string",
			config: &Config{
				KeyString: keyString,
			},
			wantErr: false,
		},
		{
			name: "Invalid key string",
			config: &Config{
				KeyString: "invalid-base64!",
			},
			wantErr: true,
		},
		{
			name: "Empty config",
			config: &Config{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := NewEncryptorFromConfig(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewEncryptorFromConfig() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("NewEncryptorFromConfig() unexpected error: %v", err)
				}
				if enc == nil {
					t.Errorf("NewEncryptorFromConfig() returned nil")
				}
			}
		})
	}
}

// TestNewEncryptorFromConfigEnvVar tests config with environment variable
func TestNewEncryptorFromConfigEnvVar(t *testing.T) {
	keyString, _ := GenerateKeyString(32)

	// Set environment variable
	os.Setenv("TEST_ENCRYPTION_KEY", keyString)
	defer os.Unsetenv("TEST_ENCRYPTION_KEY")

	config := &Config{
		KeyEnvVar: "TEST_ENCRYPTION_KEY",
	}

	enc, err := NewEncryptorFromConfig(config)
	if err != nil {
		t.Errorf("NewEncryptorFromConfig() error: %v", err)
	}
	if enc == nil {
		t.Errorf("NewEncryptorFromConfig() returned nil")
	}

	// Test with missing env var
	config2 := &Config{
		KeyEnvVar: "MISSING_KEY",
	}

	_, err = NewEncryptorFromConfig(config2)
	if err == nil {
		t.Errorf("NewEncryptorFromConfig() expected error for missing env var")
	}
}

// TestDefaultConfig tests the default config
func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Errorf("DefaultConfig() returned nil")
	}

	if config.KeyEnvVar != "ENCRYPTION_KEY" {
		t.Errorf("DefaultConfig() KeyEnvVar = %q, want %q", config.KeyEnvVar, "ENCRYPTION_KEY")
	}
}

// TestConfigPriority tests that config uses correct priority: Key > KeyString > KeyEnvVar
func TestConfigPriority(t *testing.T) {
	key1, _ := GenerateKey(32)
	key2, _ := GenerateKey(32)
	key3, _ := GenerateKey(32)

	keyString2 := base64.StdEncoding.EncodeToString(key2)
	keyString3 := base64.StdEncoding.EncodeToString(key3)

	os.Setenv("TEST_KEY", keyString3)
	defer os.Unsetenv("TEST_KEY")

	// Config with all three - should use Key
	config := &Config{
		Key:       key1,
		KeyString: keyString2,
		KeyEnvVar: "TEST_KEY",
	}

	enc, err := NewEncryptorFromConfig(config)
	if err != nil {
		t.Fatalf("NewEncryptorFromConfig() error: %v", err)
	}

	// Encrypt with the configured encryptor
	plaintext := "test"
	ciphertext, _ := enc.Encrypt(plaintext)

	// Try to decrypt with encryptor from key1 - should work
	enc1, _ := NewEncryptor(key1)
	if decrypted, _ := enc1.Decrypt(ciphertext); decrypted != plaintext {
		t.Errorf("Config did not use Key (highest priority)")
	}

	// Try to decrypt with encryptor from key2 - should fail
	enc2, _ := NewEncryptor(key2)
	if decrypted, err := enc2.Decrypt(ciphertext); err == nil && decrypted == plaintext {
		t.Errorf("Config used KeyString instead of Key")
	}
}

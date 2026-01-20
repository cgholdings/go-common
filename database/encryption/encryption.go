package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrInvalidKeySize is returned when the encryption key size is invalid
	ErrInvalidKeySize = errors.New("encryption key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256")
	// ErrEncryptionFailed is returned when encryption fails
	ErrEncryptionFailed = errors.New("encryption failed")
	// ErrDecryptionFailed is returned when decryption fails
	ErrDecryptionFailed = errors.New("decryption failed")
	// ErrInvalidCiphertext is returned when the ciphertext is invalid
	ErrInvalidCiphertext = errors.New("invalid ciphertext: too short or malformed")
)

// Encryptor handles encryption and decryption operations
type Encryptor struct {
	key []byte
}

// NewEncryptor creates a new Encryptor with the provided key
// The key should be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	return &Encryptor{
		key: key,
	}, nil
}

// NewEncryptorFromString creates a new Encryptor from a base64-encoded key string
func NewEncryptorFromString(keyString string) (*Encryptor, error) {
	key, err := base64.StdEncoding.DecodeString(keyString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	return NewEncryptor(key)
}

// Encrypt encrypts the plaintext using AES-256-GCM
// Returns base64-encoded ciphertext with nonce prepended
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("%w: failed to generate nonce: %v", ErrEncryptionFailed, err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the base64-encoded ciphertext using AES-256-GCM
func (e *Encryptor) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("%w: invalid base64: %v", ErrDecryptionFailed, err)
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", ErrInvalidCiphertext
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return string(plaintext), nil
}

// GenerateKey generates a random encryption key of the specified size
// size should be 16, 24, or 32 for AES-128, AES-192, or AES-256
func GenerateKey(size int) ([]byte, error) {
	if size != 16 && size != 24 && size != 32 {
		return nil, ErrInvalidKeySize
	}

	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return key, nil
}

// GenerateKeyString generates a random encryption key and returns it as a base64-encoded string
func GenerateKeyString(size int) (string, error) {
	key, err := GenerateKey(size)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(key), nil
}

// Hash generates a SHA-256 hash of the input string
// This is useful for creating searchable hashes of encrypted fields
// Returns a hex-encoded hash string
func Hash(value string) string {
	if value == "" {
		return ""
	}

	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

// HashBytes generates a SHA-256 hash of the input bytes
// Returns a hex-encoded hash string
func HashBytes(value []byte) string {
	if len(value) == 0 {
		return ""
	}

	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

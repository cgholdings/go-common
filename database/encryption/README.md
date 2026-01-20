# Database Encryption Package

A GORM plugin for automatic field-level encryption and hashing in MySQL databases. Simply annotate your struct fields with tags, and GORM will automatically encrypt/decrypt them.

## Features

- **Automatic Encryption/Decryption**: Uses AES-256-GCM for secure encryption
- **Tag-Based Configuration**: Mark fields with `encrypt:"true"` tag
- **Searchable Hashing**: Generate searchable hashes with `hash:"FieldName"` tag
- **GORM Integration**: Seamless integration with GORM hooks
- **Thread-Safe**: Safe for concurrent operations
- **Field Caching**: Optimized performance with reflection caching

## Installation

```bash
go get github.com/cgholdings/go-common/database/encryption
```

## Quick Start

### 1. Define Your Model

```go
type User struct {
    ID          uint   `gorm:"primarykey"`
    Name        string
    Email       string
    SSN         string `gorm:"type:text" encrypt:"true"`
    SSNHash     string `gorm:"type:varchar(64);index" hash:"SSN"`
    CreditCard  string `gorm:"type:text" encrypt:"true"`
    CCHash      string `gorm:"type:varchar(64);index" hash:"CreditCard"`
}
```

### 2. Setup GORM with Encryption Plugin

```go
package main

import (
    "github.com/cgholdings/go-common/database/encryption"
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
)

func main() {
    // Generate a new encryption key (do this once and save it securely)
    key, err := encryption.GenerateKey(32) // 32 bytes = AES-256
    if err != nil {
        panic(err)
    }

    // Create encryptor
    encryptor, err := encryption.NewEncryptor(key)
    if err != nil {
        panic(err)
    }

    // Setup database
    dsn := "user:pass@tcp(127.0.0.1:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local"
    db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
    if err != nil {
        panic(err)
    }

    // Register encryption plugin
    db.Use(encryption.NewPlugin(encryptor))

    // Auto migrate
    db.AutoMigrate(&User{})
}
```

### 3. Use Your Models Normally

```go
// Create - automatic encryption
user := User{
    Name:       "John Doe",
    Email:      "john@example.com",
    SSN:        "123-45-6789",
    CreditCard: "4111111111111111",
}
db.Create(&user)
// SSN and CreditCard are encrypted in database
// SSNHash and CCHash are automatically populated with hashes

// Query - automatic decryption
var retrieved User
db.First(&retrieved, user.ID)
fmt.Println(retrieved.SSN) // "123-45-6789" - decrypted automatically

// Search by hash
ssnHash := encryption.Hash("123-45-6789")
var found User
db.Where("ssn_hash = ?", ssnHash).First(&found)
// SSN is still encrypted in database but decrypted when retrieved

// Update - automatic re-encryption
retrieved.SSN = "999-88-7777"
db.Save(&retrieved)
// New SSN is encrypted, and SSNHash is updated automatically
```

## Configuration Options

### Using Environment Variables

```go
// Set environment variable
// export ENCRYPTION_KEY="base64-encoded-key-here"

config := encryption.DefaultConfig()
encryptor, err := encryption.NewEncryptorFromConfig(config)
if err != nil {
    panic(err)
}

db.Use(encryption.NewPlugin(encryptor))
```

### Using Base64 Key String

```go
// Generate key string once and save it
keyString, _ := encryption.GenerateKeyString(32)
fmt.Println(keyString) // Save this in your config

// Later, load from config
config := &encryption.Config{
    KeyString: "your-base64-encoded-key-here",
}

encryptor, err := encryption.NewEncryptorFromConfig(config)
if err != nil {
    panic(err)
}

db.Use(encryption.NewPlugin(encryptor))
```

### Using Custom Environment Variable

```go
config := &encryption.Config{
    KeyEnvVar: "MY_CUSTOM_KEY_VAR",
}

encryptor, err := encryption.NewEncryptorFromConfig(config)
if err != nil {
    panic(err)
}

db.Use(encryption.NewPlugin(encryptor))
```

## Key Management

### Generating Keys

```go
// Generate 32-byte key for AES-256 (recommended)
key, err := encryption.GenerateKey(32)

// Generate 24-byte key for AES-192
key, err := encryption.GenerateKey(24)

// Generate 16-byte key for AES-128
key, err := encryption.GenerateKey(16)

// Generate as base64 string
keyString, err := encryption.GenerateKeyString(32)
fmt.Println(keyString) // Store this securely
```

### Storing Keys Securely

**DO NOT** hardcode keys in your source code. Use one of these methods:

1. **Environment Variables** (Recommended for development)
```bash
export ENCRYPTION_KEY="your-base64-key"
```

2. **Secret Management Services** (Recommended for production)
   - AWS Secrets Manager
   - HashiCorp Vault
   - Google Secret Manager
   - Azure Key Vault

3. **Configuration Files** (with proper permissions)
```go
// Load from encrypted config file
keyString := loadFromSecureConfig()
config := &encryption.Config{KeyString: keyString}
```

## Usage Examples

### Encryption Tag Options

```go
type Model struct {
    Field1 string `encrypt:"true"`   // ✓ Will be encrypted
    Field2 string `encrypt:"1"`      // ✓ Will be encrypted
    Field3 string `encrypt:"yes"`    // ✓ Will be encrypted
    Field4 string `encrypt:"false"`  // ✗ Not encrypted
    Field5 string `encrypt:"no"`     // ✗ Not encrypted
    Field6 string `encrypt:"0"`      // ✗ Not encrypted
    Field7 string                     // ✗ Not encrypted (no tag)
}
```

### Hash Tag for Searchable Fields

The hash tag creates a searchable hash of another field:

```go
type User struct {
    Email      string `gorm:"type:text" encrypt:"true"`
    EmailHash  string `gorm:"type:varchar(64);index" hash:"Email"`
}

// Search by email without decrypting all records
emailHash := encryption.Hash("user@example.com")
db.Where("email_hash = ?", emailHash).First(&user)
```

### Manual Encryption/Decryption

You can also use the encryptor manually:

```go
encryptor, _ := encryption.NewEncryptor(key)

// Encrypt
ciphertext, err := encryptor.Encrypt("sensitive data")

// Decrypt
plaintext, err := encryptor.Decrypt(ciphertext)

// Hash
hash := encryption.Hash("searchable value")
```

### Batch Operations

The plugin works seamlessly with batch operations:

```go
users := []User{
    {Name: "User1", SSN: "111-11-1111"},
    {Name: "User2", SSN: "222-22-2222"},
    {Name: "User3", SSN: "333-33-3333"},
}

// All SSNs encrypted automatically
db.Create(&users)

// All SSNs decrypted automatically
var retrieved []User
db.Find(&retrieved)
```

### Handling Empty Fields

Empty strings are handled gracefully:

```go
user := User{
    Name: "John",
    SSN:  "", // Empty field
}
db.Create(&user)
// Empty fields remain empty (not encrypted)
```

## Security Best Practices

1. **Key Size**: Use 32-byte keys (AES-256) for maximum security
2. **Key Rotation**: Plan for key rotation in production
3. **Key Storage**: Never commit keys to version control
4. **Hashing**: Use hash fields for searching, never search encrypted fields directly
5. **TLS/SSL**: Always use encrypted connections to your database
6. **Access Control**: Limit access to encryption keys
7. **Audit**: Log access to encrypted data

## Performance Considerations

- **Caching**: The plugin caches struct field information for optimal performance
- **Indexes**: Create indexes on hash fields for fast searches
- **Batch Operations**: Use batch inserts/updates when possible
- **Field Selection**: Only select encrypted fields when needed

```go
// Efficient: Only get name (no decryption needed)
db.Select("name").Find(&users)

// Less efficient: Decrypts all fields
db.Find(&users)
```

## Limitations

- Only string fields are supported for encryption
- Encrypted fields cannot be used in WHERE clauses (use hash fields instead)
- Encrypted field length will be longer than plaintext (use `type:text` in GORM)

## Database Schema Considerations

### Encrypted Field Column Types

Encrypted data is base64-encoded and includes a nonce. The ciphertext will be longer than the plaintext:

```go
// Good - use TEXT for encrypted fields
SSN string `gorm:"type:text" encrypt:"true"`

// Bad - VARCHAR may truncate
SSN string `gorm:"type:varchar(100)" encrypt:"true"` // May be too short!
```

### Hash Field Column Types

Hash fields always produce 64-character hex strings:

```go
// Perfect size for SHA-256 hashes
SSNHash string `gorm:"type:varchar(64);index" hash:"SSN"`
```

### Recommended Schema

```sql
CREATE TABLE users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255),
    email VARCHAR(255),
    ssn TEXT,                    -- Encrypted field (TEXT type)
    ssn_hash VARCHAR(64),        -- Hash field for searching
    credit_card TEXT,            -- Encrypted field
    cc_hash VARCHAR(64),         -- Hash field
    INDEX idx_ssn_hash (ssn_hash),
    INDEX idx_cc_hash (cc_hash)
);
```

## Troubleshooting

### Decryption Errors

If you see decryption errors, common causes:
- Wrong encryption key
- Data was not encrypted with this package
- Database column truncated the ciphertext (use TEXT type)
- Key was changed after data was encrypted

### Performance Issues

- Add indexes to hash fields used in WHERE clauses
- Use `Select()` to limit fields retrieved
- Consider using read replicas for queries
- Monitor query performance with GORM's logger

## Examples

See the `*_test.go` files for comprehensive examples of:
- Basic encryption/decryption
- GORM integration
- Hash-based searching
- Batch operations
- Configuration options

## License

MIT License - see LICENSE file for details

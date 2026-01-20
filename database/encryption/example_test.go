package encryption_test

import (
	"fmt"
	"log"

	"github.com/cgholdings/go-common/database/encryption"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// User model with encrypted fields
type User struct {
	ID         uint   `gorm:"primarykey"`
	Name       string `gorm:"type:varchar(255)"`
	Email      string `gorm:"type:varchar(255)"`
	SSN        string `gorm:"type:text" encrypt:"true"`
	SSNHash    string `gorm:"type:varchar(64);index" hash:"SSN"`
	CreditCard string `gorm:"type:text" encrypt:"true"`
	CCHash     string `gorm:"type:varchar(64);index" hash:"CreditCard"`
}

// ExampleBasicUsage demonstrates basic encryption/decryption
func ExampleBasicUsage() {
	// Generate a new encryption key (32 bytes for AES-256)
	key, err := encryption.GenerateKey(32)
	if err != nil {
		log.Fatal(err)
	}

	// Create encryptor
	encryptor, err := encryption.NewEncryptor(key)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt data
	plaintext := "sensitive-data-123"
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Encrypted: %s\n", ciphertext)

	// Decrypt data
	decrypted, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)
}

// ExampleGORMIntegration demonstrates GORM plugin usage
func ExampleGORMIntegration() {
	// Generate encryption key
	key, err := encryption.GenerateKey(32)
	if err != nil {
		log.Fatal(err)
	}

	// Create encryptor
	encryptor, err := encryption.NewEncryptor(key)
	if err != nil {
		log.Fatal(err)
	}

	// Setup database
	dsn := "user:pass@tcp(127.0.0.1:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	// Register encryption plugin
	if err := db.Use(encryption.NewPlugin(encryptor)); err != nil {
		log.Fatal(err)
	}

	// Auto migrate
	if err := db.AutoMigrate(&User{}); err != nil {
		log.Fatal(err)
	}

	// Create user - SSN and CreditCard will be encrypted automatically
	user := User{
		Name:       "John Doe",
		Email:      "john@example.com",
		SSN:        "123-45-6789",
		CreditCard: "4111111111111111",
	}

	if err := db.Create(&user).Error; err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created user with ID: %d\n", user.ID)
	fmt.Printf("SSN Hash: %s\n", user.SSNHash)

	// Query user - encrypted fields will be decrypted automatically
	var retrieved User
	if err := db.First(&retrieved, user.ID).Error; err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Retrieved SSN: %s\n", retrieved.SSN)
}

// ExampleSearchByHash demonstrates searching encrypted fields using hashes
func ExampleSearchByHash() {
	// Setup (omitted for brevity - see ExampleGORMIntegration)
	var db *gorm.DB

	// Search for a user by SSN using the hash
	searchSSN := "123-45-6789"
	ssnHash := encryption.Hash(searchSSN)

	var user User
	if err := db.Where("ssn_hash = ?", ssnHash).First(&user).Error; err != nil {
		log.Fatal(err)
	}

	// The SSN field is automatically decrypted
	fmt.Printf("Found user: %s, SSN: %s\n", user.Name, user.SSN)
}

// ExampleConfigFromEnvironment demonstrates loading config from environment
func ExampleConfigFromEnvironment() {
	// Set environment variable: export ENCRYPTION_KEY="base64-encoded-key"

	// Load config from default environment variable
	config := encryption.DefaultConfig()

	encryptor, err := encryption.NewEncryptorFromConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	// Use encryptor...
	fmt.Printf("Encryptor created from environment variable\n")
}

// ExampleConfigFromString demonstrates using a base64-encoded key
func ExampleConfigFromString() {
	// Generate a key string once and save it securely
	keyString, err := encryption.GenerateKeyString(32)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated key (save this securely): %s\n", keyString)

	// Later, load from config
	config := &encryption.Config{
		KeyString: keyString,
	}

	encryptor, err := encryption.NewEncryptorFromConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	// Use encryptor...
	_ = encryptor
}

// ExampleHashForSearching demonstrates manual hashing
func ExampleHashForSearching() {
	// Hash a value for searching
	ssn := "123-45-6789"
	hash := encryption.Hash(ssn)

	fmt.Printf("SSN: %s\n", ssn)
	fmt.Printf("Hash: %s\n", hash)

	// Hash is deterministic
	hash2 := encryption.Hash(ssn)
	fmt.Printf("Hashes match: %v\n", hash == hash2)

	// Different values produce different hashes
	hash3 := encryption.Hash("999-88-7777")
	fmt.Printf("Different hashes: %v\n", hash != hash3)
}

// ExampleBatchOperations demonstrates batch create and query
func ExampleBatchOperations() {
	// Setup (omitted for brevity)
	var db *gorm.DB

	// Create multiple users - all encrypted automatically
	users := []User{
		{Name: "User1", SSN: "111-11-1111", CreditCard: "4111111111111111"},
		{Name: "User2", SSN: "222-22-2222", CreditCard: "4222222222222222"},
		{Name: "User3", SSN: "333-33-3333", CreditCard: "4333333333333333"},
	}

	if err := db.Create(&users).Error; err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created %d users\n", len(users))

	// Query all users - all decrypted automatically
	var retrieved []User
	if err := db.Find(&retrieved).Error; err != nil {
		log.Fatal(err)
	}

	for _, user := range retrieved {
		fmt.Printf("User: %s, SSN: %s\n", user.Name, user.SSN)
	}
}

// ExampleUpdateEncryptedField demonstrates updating encrypted fields
func ExampleUpdateEncryptedField() {
	// Setup (omitted for brevity)
	var db *gorm.DB
	var user User

	// Update SSN - will be re-encrypted automatically
	user.SSN = "999-88-7777"

	if err := db.Save(&user).Error; err != nil {
		log.Fatal(err)
	}

	// SSNHash is also updated automatically
	fmt.Printf("Updated SSN, new hash: %s\n", user.SSNHash)
}

package encryption

import (
	"reflect"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// testModel is a test model with encrypted fields
type testModel struct {
	ID        uint   `gorm:"primarykey"`
	Name      string // Not encrypted
	SSN       string `gorm:"type:text" encrypt:"true"`
	SSNHash   string `gorm:"type:varchar(64);index" hash:"SSN"`
	CreditCard string `gorm:"type:text" encrypt:"true"`
	CCHash    string `gorm:"type:varchar(64);index" hash:"CreditCard"`
}

// setupTestDB creates a test database with the encryption plugin
func setupTestDB(t *testing.T) (*gorm.DB, *Encryptor) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	key, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	encryptor, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	plugin := NewPlugin(encryptor)
	if err := db.Use(plugin); err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	if err := db.AutoMigrate(&testModel{}); err != nil {
		t.Fatalf("Failed to migrate: %v", err)
	}

	return db, encryptor
}

// TestPluginName tests the plugin name
func TestPluginName(t *testing.T) {
	key, _ := GenerateKey(32)
	encryptor, _ := NewEncryptor(key)
	plugin := NewPlugin(encryptor)

	if plugin.Name() != PluginName {
		t.Errorf("Name() = %q, want %q", plugin.Name(), PluginName)
	}
}

// TestPluginEncryptDecrypt tests automatic encryption and decryption
func TestPluginEncryptDecrypt(t *testing.T) {
	db, _ := setupTestDB(t)

	// Create a record
	model := testModel{
		Name:       "John Doe",
		SSN:        "123-45-6789",
		CreditCard: "4111111111111111",
	}

	if err := db.Create(&model).Error; err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Get the raw data from database to verify encryption
	var rawData map[string]interface{}
	db.Table("test_models").Where("id = ?", model.ID).Take(&rawData)

	// SSN should be encrypted in database (not equal to plaintext)
	if rawSSN, ok := rawData["ssn"].(string); ok {
		if rawSSN == "123-45-6789" {
			t.Errorf("SSN was not encrypted in database")
		}
	}

	// CreditCard should be encrypted in database
	if rawCC, ok := rawData["credit_card"].(string); ok {
		if rawCC == "4111111111111111" {
			t.Errorf("CreditCard was not encrypted in database")
		}
	}

	// Query the record
	var retrieved testModel
	if err := db.First(&retrieved, model.ID).Error; err != nil {
		t.Fatalf("First() error: %v", err)
	}

	// Verify decryption worked
	if retrieved.SSN != "123-45-6789" {
		t.Errorf("SSN decryption failed: got %q, want %q", retrieved.SSN, "123-45-6789")
	}

	if retrieved.CreditCard != "4111111111111111" {
		t.Errorf("CreditCard decryption failed: got %q, want %q", retrieved.CreditCard, "4111111111111111")
	}

	// Non-encrypted field should remain unchanged
	if retrieved.Name != "John Doe" {
		t.Errorf("Name changed: got %q, want %q", retrieved.Name, "John Doe")
	}
}

// TestPluginUpdate tests encryption on update
func TestPluginUpdate(t *testing.T) {
	db, _ := setupTestDB(t)

	// Create a record
	model := testModel{
		Name:       "Jane Doe",
		SSN:        "111-22-3333",
		CreditCard: "5500000000000004",
	}

	if err := db.Create(&model).Error; err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Update the encrypted field
	model.SSN = "999-88-7777"
	if err := db.Save(&model).Error; err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Retrieve and verify
	var retrieved testModel
	if err := db.First(&retrieved, model.ID).Error; err != nil {
		t.Fatalf("First() error: %v", err)
	}

	if retrieved.SSN != "999-88-7777" {
		t.Errorf("SSN update failed: got %q, want %q", retrieved.SSN, "999-88-7777")
	}
}

// TestPluginBatchOperations tests encryption on batch operations
func TestPluginBatchOperations(t *testing.T) {
	db, _ := setupTestDB(t)

	// Create multiple records
	models := []testModel{
		{Name: "User1", SSN: "111-11-1111", CreditCard: "4111111111111111"},
		{Name: "User2", SSN: "222-22-2222", CreditCard: "4222222222222222"},
		{Name: "User3", SSN: "333-33-3333", CreditCard: "4333333333333333"},
	}

	if err := db.Create(&models).Error; err != nil {
		t.Fatalf("Create() batch error: %v", err)
	}

	// Query all records
	var retrieved []testModel
	if err := db.Find(&retrieved).Error; err != nil {
		t.Fatalf("Find() error: %v", err)
	}

	if len(retrieved) != 3 {
		t.Fatalf("Find() returned %d records, want 3", len(retrieved))
	}

	// Verify all records are decrypted correctly
	for i, r := range retrieved {
		if r.SSN != models[i].SSN {
			t.Errorf("Record %d SSN mismatch: got %q, want %q", i, r.SSN, models[i].SSN)
		}
		if r.CreditCard != models[i].CreditCard {
			t.Errorf("Record %d CreditCard mismatch: got %q, want %q", i, r.CreditCard, models[i].CreditCard)
		}
	}
}

// TestPluginEmptyFields tests handling of empty encrypted fields
func TestPluginEmptyFields(t *testing.T) {
	db, _ := setupTestDB(t)

	// Create a record with empty encrypted fields
	model := testModel{
		Name:       "Empty User",
		SSN:        "",
		CreditCard: "",
	}

	if err := db.Create(&model).Error; err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Retrieve and verify
	var retrieved testModel
	if err := db.First(&retrieved, model.ID).Error; err != nil {
		t.Fatalf("First() error: %v", err)
	}

	if retrieved.SSN != "" {
		t.Errorf("Empty SSN became %q after encryption/decryption", retrieved.SSN)
	}

	if retrieved.CreditCard != "" {
		t.Errorf("Empty CreditCard became %q after encryption/decryption", retrieved.CreditCard)
	}
}

// TestPluginHash tests automatic hash generation
func TestPluginHash(t *testing.T) {
	db, _ := setupTestDB(t)

	// Create a record
	model := testModel{
		Name:       "Hash Test",
		SSN:        "123-45-6789",
		CreditCard: "4111111111111111",
	}

	if err := db.Create(&model).Error; err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Verify hashes were generated
	if model.SSNHash == "" {
		t.Errorf("SSNHash was not generated")
	}

	if model.CCHash == "" {
		t.Errorf("CCHash was not generated")
	}

	// Verify hashes are correct
	expectedSSNHash := Hash("123-45-6789")
	if model.SSNHash != expectedSSNHash {
		t.Errorf("SSNHash = %q, want %q", model.SSNHash, expectedSSNHash)
	}

	expectedCCHash := Hash("4111111111111111")
	if model.CCHash != expectedCCHash {
		t.Errorf("CCHash = %q, want %q", model.CCHash, expectedCCHash)
	}

	// Test searching by hash
	var found testModel
	if err := db.Where("ssn_hash = ?", expectedSSNHash).First(&found).Error; err != nil {
		t.Fatalf("Search by hash failed: %v", err)
	}

	if found.ID != model.ID {
		t.Errorf("Search by hash found wrong record: got ID %d, want %d", found.ID, model.ID)
	}

	// Verify the encrypted field is still decrypted correctly
	if found.SSN != "123-45-6789" {
		t.Errorf("SSN after hash search: got %q, want %q", found.SSN, "123-45-6789")
	}
}

// TestPluginHashUpdate tests hash updates when source field changes
func TestPluginHashUpdate(t *testing.T) {
	db, _ := setupTestDB(t)

	// Create a record
	model := testModel{
		Name:       "Hash Update Test",
		SSN:        "111-11-1111",
		CreditCard: "4111111111111111",
	}

	if err := db.Create(&model).Error; err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	oldSSNHash := model.SSNHash

	// Update the SSN
	model.SSN = "999-99-9999"
	if err := db.Save(&model).Error; err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Hash should have been updated
	if model.SSNHash == oldSSNHash {
		t.Errorf("SSNHash was not updated after changing SSN")
	}

	expectedNewHash := Hash("999-99-9999")
	if model.SSNHash != expectedNewHash {
		t.Errorf("SSNHash = %q, want %q", model.SSNHash, expectedNewHash)
	}
}

// TestPluginHashEmpty tests hash of empty fields
func TestPluginHashEmpty(t *testing.T) {
	db, _ := setupTestDB(t)

	// Create a record with empty fields
	model := testModel{
		Name:       "Empty Hash Test",
		SSN:        "",
		CreditCard: "",
	}

	if err := db.Create(&model).Error; err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Empty fields should have empty hashes
	if model.SSNHash != "" {
		t.Errorf("SSNHash for empty SSN = %q, want empty string", model.SSNHash)
	}

	if model.CCHash != "" {
		t.Errorf("CCHash for empty CreditCard = %q, want empty string", model.CCHash)
	}
}

// TestGetEncryptedFields tests the getEncryptedFields method
func TestGetEncryptedFields(t *testing.T) {
	key, _ := GenerateKey(32)
	encryptor, _ := NewEncryptor(key)
	plugin := NewPlugin(encryptor)

	type testStruct struct {
		Normal     string
		Encrypted1 string `encrypt:"true"`
		Encrypted2 string `encrypt:"1"`
		Encrypted3 string `encrypt:"yes"`
		NotThis    string `encrypt:"false"`
		NorThis    string `encrypt:"no"`
	}

	indices := plugin.getEncryptedFields(reflect.TypeOf(testStruct{}))

	// Should find 3 encrypted fields
	if len(indices) != 3 {
		t.Errorf("getEncryptedFields() found %d fields, want 3", len(indices))
	}

	// Verify caching works
	indices2 := plugin.getEncryptedFields(reflect.TypeOf(testStruct{}))
	if len(indices2) != len(indices) {
		t.Errorf("getEncryptedFields() cache not working")
	}
}

// TestGetHashFields tests the getHashFields method
func TestGetHashFields(t *testing.T) {
	key, _ := GenerateKey(32)
	encryptor, _ := NewEncryptor(key)
	plugin := NewPlugin(encryptor)

	type testStruct struct {
		Field1     string
		Field2     string
		Field1Hash string `hash:"Field1"`
		Field2Hash string `hash:"Field2"`
	}

	mappings := plugin.getHashFields(reflect.TypeOf(testStruct{}))

	// Should find 2 hash mappings
	if len(mappings) != 2 {
		t.Errorf("getHashFields() found %d mappings, want 2", len(mappings))
	}

	// Verify caching works
	mappings2 := plugin.getHashFields(reflect.TypeOf(testStruct{}))
	if len(mappings2) != len(mappings) {
		t.Errorf("getHashFields() cache not working")
	}
}

// TestPluginWithNonStringFields tests that non-string fields are ignored
func TestPluginWithNonStringFields(t *testing.T) {
	db, _ := setupTestDB(t)

	type mixedModel struct {
		ID       uint
		Text     string `encrypt:"true"`
		Number   int    `encrypt:"true"`   // Should be ignored
		Boolean  bool   `encrypt:"true"`   // Should be ignored
		Float    float64 `encrypt:"true"`  // Should be ignored
	}

	if err := db.AutoMigrate(&mixedModel{}); err != nil {
		t.Fatalf("AutoMigrate() error: %v", err)
	}

	model := mixedModel{
		Text:    "secret",
		Number:  42,
		Boolean: true,
		Float:   3.14,
	}

	// Should not error even with non-string encrypted fields
	if err := db.Create(&model).Error; err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	var retrieved mixedModel
	if err := db.First(&retrieved, model.ID).Error; err != nil {
		t.Fatalf("First() error: %v", err)
	}

	// Non-string fields should remain unchanged
	if retrieved.Number != 42 {
		t.Errorf("Number changed: got %d, want 42", retrieved.Number)
	}
}

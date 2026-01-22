package encryption

import (
	"fmt"
	"reflect"
	"sync"

	"gorm.io/gorm"
)

const (
	// EncryptTagName is the struct tag name used to mark fields for encryption
	EncryptTagName = "encrypt"
	// HashTagName is the struct tag name used to mark fields for hashing
	HashTagName = "hash"
	// PluginName is the name of the GORM plugin
	PluginName = "encryption"
)

// Plugin is a GORM plugin that automatically encrypts and decrypts fields
type Plugin struct {
	encryptor      *Encryptor
	encryptedCache sync.Map // cache of model types and their encrypted field indices
	hashCache      sync.Map // cache of model types and their hash field mappings
}

// NewPlugin creates a new encryption plugin for GORM
func NewPlugin(encryptor *Encryptor) *Plugin {
	return &Plugin{
		encryptor: encryptor,
	}
}

// Name returns the plugin name
func (p *Plugin) Name() string {
	return PluginName
}

// Initialize initializes the plugin and registers callbacks
func (p *Plugin) Initialize(db *gorm.DB) error {
	// Register callbacks for Create operations
	if err := db.Callback().Create().Before("gorm:create").Register("encryption:before_create", p.beforeCreate); err != nil {
		return fmt.Errorf("failed to register before_create callback: %w", err)
	}

	// Register callbacks for Update operations
	if err := db.Callback().Update().Before("gorm:update").Register("encryption:before_update", p.beforeUpdate); err != nil {
		return fmt.Errorf("failed to register before_update callback: %w", err)
	}

	// Register callbacks for Query operations
	if err := db.Callback().Query().After("gorm:after_query").Register("encryption:after_query", p.afterQuery); err != nil {
		return fmt.Errorf("failed to register after_query callback: %w", err)
	}

	// Register callbacks for Row operations
	if err := db.Callback().Row().After("gorm:row").Register("encryption:after_row", p.afterQuery); err != nil {
		return fmt.Errorf("failed to register after_row callback: %w", err)
	}

	return nil
}

// beforeCreate encrypts fields and populates hash fields before creating a record
func (p *Plugin) beforeCreate(db *gorm.DB) {
	if db.Error != nil {
		return
	}

	// Hash fields first (before encryption)
	if err := p.hashFields(db.Statement.ReflectValue); err != nil {
		db.AddError(fmt.Errorf("hashing before create failed: %w", err))
		return
	}

	if err := p.encryptFields(db.Statement.ReflectValue); err != nil {
		db.AddError(fmt.Errorf("encryption before create failed: %w", err))
	}
}

// beforeUpdate encrypts fields and populates hash fields before updating a record
func (p *Plugin) beforeUpdate(db *gorm.DB) {
	if db.Error != nil {
		return
	}

	// Hash fields first (before encryption)
	if err := p.hashFields(db.Statement.ReflectValue); err != nil {
		db.AddError(fmt.Errorf("hashing before update failed: %w", err))
		return
	}

	if err := p.encryptFields(db.Statement.ReflectValue); err != nil {
		db.AddError(fmt.Errorf("encryption before update failed: %w", err))
	}
}

// afterQuery decrypts fields after querying records
func (p *Plugin) afterQuery(db *gorm.DB) {
	if db.Error != nil {
		return
	}

	if err := p.decryptFields(db.Statement.ReflectValue); err != nil {
		db.AddError(fmt.Errorf("decryption after query failed: %w", err))
	}
}

// encryptFields encrypts all fields marked with the encrypt tag
func (p *Plugin) encryptFields(rv reflect.Value) error {
	if !rv.IsValid() {
		return nil
	}

	// Handle pointer
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}

	// Handle slice/array (batch operations)
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
		for i := 0; i < rv.Len(); i++ {
			if err := p.encryptFields(rv.Index(i)); err != nil {
				return err
			}
		}
		return nil
	}

	// Only process structs
	if rv.Kind() != reflect.Struct {
		return nil
	}

	encryptedFields := p.getEncryptedFields(rv.Type())
	for _, fieldIndex := range encryptedFields {
		field := rv.Field(fieldIndex)

		// Handle pointer to string
		if field.Kind() == reflect.Ptr {
			if field.IsNil() {
				continue
			}
			// Dereference the pointer
			field = field.Elem()
		}

		// Only encrypt string fields
		if field.Kind() != reflect.String {
			continue
		}

		plaintext := field.String()
		if plaintext == "" {
			continue
		}

		ciphertext, err := p.encryptor.Encrypt(plaintext)
		if err != nil {
			return fmt.Errorf("failed to encrypt field %s: %w", rv.Type().Field(fieldIndex).Name, err)
		}

		field.SetString(ciphertext)
	}

	return nil
}

// decryptFields decrypts all fields marked with the encrypt tag
func (p *Plugin) decryptFields(rv reflect.Value) error {
	if !rv.IsValid() {
		return nil
	}

	// Handle pointer
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}

	// Handle slice/array (batch operations)
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
		for i := 0; i < rv.Len(); i++ {
			if err := p.decryptFields(rv.Index(i)); err != nil {
				return err
			}
		}
		return nil
	}

	// Only process structs
	if rv.Kind() != reflect.Struct {
		return nil
	}

	encryptedFields := p.getEncryptedFields(rv.Type())
	for _, fieldIndex := range encryptedFields {
		field := rv.Field(fieldIndex)

		// Handle pointer to string
		if field.Kind() == reflect.Ptr {
			if field.IsNil() {
				continue
			}
			// Dereference the pointer
			field = field.Elem()
		}

		// Only decrypt string fields
		if field.Kind() != reflect.String {
			continue
		}

		ciphertext := field.String()
		if ciphertext == "" {
			continue
		}

		plaintext, err := p.encryptor.Decrypt(ciphertext)
		if err != nil {
			return fmt.Errorf("failed to decrypt field %s: %w", rv.Type().Field(fieldIndex).Name, err)
		}

		field.SetString(plaintext)
	}

	return nil
}

// getEncryptedFields returns the indices of fields that should be encrypted
// Results are cached for performance
func (p *Plugin) getEncryptedFields(t reflect.Type) []int {
	// Check cache first
	if cached, ok := p.encryptedCache.Load(t); ok {
		return cached.([]int)
	}

	var indices []int
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Check if field has the encrypt tag
		if tag, ok := field.Tag.Lookup(EncryptTagName); ok {
			// Accept "true", "1", "yes", or any non-empty value
			if tag == "true" || tag == "1" || tag == "yes" || tag != "" && tag != "false" && tag != "0" && tag != "no" {
				// Support string and *string (pointer to string) fields
				fieldKind := field.Type.Kind()
				if fieldKind == reflect.String {
					indices = append(indices, i)
				} else if fieldKind == reflect.Ptr && field.Type.Elem().Kind() == reflect.String {
					// Pointer to string
					indices = append(indices, i)
				}
			}
		}
	}

	// Cache the result
	p.encryptedCache.Store(t, indices)

	return indices
}

// hashFieldMapping represents a mapping from a hash field to its source field
type hashFieldMapping struct {
	hashFieldIndex   int    // index of the field that will store the hash
	sourceFieldIndex int    // index of the field to hash
	sourceFieldName  string // name of the field to hash
}

// hashFields populates hash fields with hashes of their source fields
func (p *Plugin) hashFields(rv reflect.Value) error {
	if !rv.IsValid() {
		return nil
	}

	// Handle pointer
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}

	// Handle slice/array (batch operations)
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
		for i := 0; i < rv.Len(); i++ {
			if err := p.hashFields(rv.Index(i)); err != nil {
				return err
			}
		}
		return nil
	}

	// Only process structs
	if rv.Kind() != reflect.Struct {
		return nil
	}

	hashMappings := p.getHashFields(rv.Type())
	for _, mapping := range hashMappings {
		sourceField := rv.Field(mapping.sourceFieldIndex)
		hashField := rv.Field(mapping.hashFieldIndex)

		// Only hash string fields
		if sourceField.Kind() != reflect.String || hashField.Kind() != reflect.String {
			continue
		}

		sourceValue := sourceField.String()
		hashValue := Hash(sourceValue)

		hashField.SetString(hashValue)
	}

	return nil
}

// getHashFields returns the hash field mappings for a struct type
// Results are cached for performance
func (p *Plugin) getHashFields(t reflect.Type) []hashFieldMapping {
	// Check cache first
	if cached, ok := p.hashCache.Load(t); ok {
		return cached.([]hashFieldMapping)
	}

	var mappings []hashFieldMapping
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Check if field has the hash tag
		if sourceFieldName, ok := field.Tag.Lookup(HashTagName); ok && sourceFieldName != "" {
			// Find the source field by name
			sourceField, found := t.FieldByName(sourceFieldName)
			if !found {
				// Log warning but continue processing other fields
				continue
			}

			// Only support string fields for both hash and source
			if field.Type.Kind() == reflect.String && sourceField.Type.Kind() == reflect.String {
				mappings = append(mappings, hashFieldMapping{
					hashFieldIndex:   i,
					sourceFieldIndex: sourceField.Index[0], // Use first index for simple fields
					sourceFieldName:  sourceFieldName,
				})
			}
		}
	}

	// Cache the result
	p.hashCache.Store(t, mappings)

	return mappings
}

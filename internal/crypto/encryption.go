package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
)

// FieldEncryptor provides AES-256-GCM encryption for sensitive fields
type FieldEncryptor struct {
	keys           map[int][]byte
	currentVersion int
	hmacSecret     []byte
	mu             sync.RWMutex
}

// NewFieldEncryptor creates a new field encryptor with versioned keys
func NewFieldEncryptor(keysBase64 []string, currentVersion int, hmacSecretBase64 string) (*FieldEncryptor, error) {
	if len(keysBase64) == 0 {
		return nil, errors.New("at least one encryption key is required")
	}

	keys := make(map[int][]byte)
	for i, keyB64 := range keysBase64 {
		key, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key %d: %w", i+1, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("key %d must be 32 bytes for AES-256, got %d", i+1, len(key))
		}
		keys[i+1] = key
	}

	if _, exists := keys[currentVersion]; !exists {
		return nil, fmt.Errorf("current version %d not found in keys", currentVersion)
	}

	hmacSecret, err := base64.StdEncoding.DecodeString(hmacSecretBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode HMAC secret: %w", err)
	}

	return &FieldEncryptor{
		keys:           keys,
		currentVersion: currentVersion,
		hmacSecret:     hmacSecret,
	}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the current key version
func (e *FieldEncryptor) Encrypt(plaintext string) (string, int, error) {
	e.mu.RLock()
	key := e.keys[e.currentVersion]
	version := e.currentVersion
	e.mu.RUnlock()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", 0, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	return encoded, version, nil
}

// Decrypt decrypts ciphertext using the specified key version
func (e *FieldEncryptor) Decrypt(ciphertext string, keyVersion int) (string, error) {
	e.mu.RLock()
	key, exists := e.keys[keyVersion]
	e.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("key version %d not found", keyVersion)
	}

	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(decoded) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := decoded[:nonceSize], decoded[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// Hash creates a deterministic hash for lookups (SHA-256)
func (e *FieldEncryptor) Hash(value string) string {
	h := sha256.New()
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

// HMAC creates an HMAC-SHA256 signature for non-repudiation
func (e *FieldEncryptor) HMAC(data string) string {
	h := hmac.New(sha256.New, e.hmacSecret)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMAC verifies an HMAC signature
func (e *FieldEncryptor) VerifyHMAC(data, signature string) bool {
	expected := e.HMAC(data)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// GenerateHashChain creates a hash linking the current record to the previous one
func (e *FieldEncryptor) GenerateHashChain(prevHash string, currentData []byte) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(currentData)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHashChain verifies that a record belongs to the chain
func (e *FieldEncryptor) VerifyHashChain(prevHash string, currentData []byte, expectedHash string) bool {
	calculated := e.GenerateHashChain(prevHash, currentData)
	return calculated == expectedHash
}

// CurrentKeyVersion returns the current encryption key version
func (e *FieldEncryptor) CurrentKeyVersion() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.currentVersion
}

// ReEncrypt decrypts with old version and re-encrypts with current version
func (e *FieldEncryptor) ReEncrypt(ciphertext string, oldVersion int) (string, int, error) {
	plaintext, err := e.Decrypt(ciphertext, oldVersion)
	if err != nil {
		return "", 0, err
	}
	return e.Encrypt(plaintext)
}

// RotateKey adds a new key and makes it the current version
func (e *FieldEncryptor) RotateKey(newKeyBase64 string, newVersion int) error {
	newKey, err := base64.StdEncoding.DecodeString(newKeyBase64)
	if err != nil {
		return fmt.Errorf("failed to decode new key: %w", err)
	}
	if len(newKey) != 32 {
		return fmt.Errorf("new key must be 32 bytes for AES-256, got %d", len(newKey))
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.keys[newVersion] = newKey
	e.currentVersion = newVersion

	return nil
}

// GenerateDigitalSignature creates a signature for audit records
func (e *FieldEncryptor) GenerateDigitalSignature(eventID, userID, action, timestamp, result string) string {
	// Concatenate all critical fields for signing
	data := fmt.Sprintf("%s|%s|%s|%s|%s", eventID, userID, action, timestamp, result)
	return e.HMAC(data)
}

// VerifyDigitalSignature verifies an audit record's digital signature
func (e *FieldEncryptor) VerifyDigitalSignature(eventID, userID, action, timestamp, result, signature string) bool {
	data := fmt.Sprintf("%s|%s|%s|%s|%s", eventID, userID, action, timestamp, result)
	return e.VerifyHMAC(data, signature)
}

// MaskPII masks personally identifiable information for logging
func MaskPII(value string, piiType string) string {
	if len(value) == 0 {
		return ""
	}

	switch piiType {
	case "email":
		return maskEmail(value)
	case "phone":
		return maskPhone(value)
	case "ssn":
		return maskSSN(value)
	case "account":
		return maskAccount(value)
	case "name":
		return maskName(value)
	default:
		return "***MASKED***"
	}
}

func maskEmail(email string) string {
	if len(email) < 3 {
		return "***"
	}
	atIdx := -1
	for i, c := range email {
		if c == '@' {
			atIdx = i
			break
		}
	}
	if atIdx <= 0 {
		return "***"
	}
	return string(email[0]) + "***" + email[atIdx:]
}

func maskPhone(phone string) string {
	if len(phone) < 4 {
		return "****"
	}
	return phone[:2] + "***" + phone[len(phone)-4:]
}

func maskSSN(ssn string) string {
	if len(ssn) < 4 {
		return "***"
	}
	return "***-**-" + ssn[len(ssn)-4:]
}

func maskAccount(account string) string {
	if len(account) < 4 {
		return "****"
	}
	return "****" + account[len(account)-4:]
}

func maskName(name string) string {
	if len(name) < 2 {
		return "***"
	}
	return string(name[0]) + "***"
}

package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSignAndValidate(t *testing.T) {
	secret := "test-secret-key"
	keyID := "key-1"

	signer := NewSigner(keyID, secret)
	validator := NewValidator(map[string]string{keyID: secret})

	headers, err := signer.SignRequest("POST", "/api/v1/webhook", []byte(`{"event":"test"}`))
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	err = validator.ValidateRequest("POST", "/api/v1/webhook", headers, []byte(`{"event":"test"}`))
	if err != nil {
		t.Fatalf("ValidateRequest failed: %v", err)
	}
}

func TestExpiredTimestamp(t *testing.T) {
	secret := "test-secret-key"
	keyID := "key-1"

	validator := NewValidator(map[string]string{keyID: secret})

	expiredTime := time.Now().Add(-10 * time.Minute)
	timestamp := strconv.FormatInt(expiredTime.Unix(), 10)
	nonce := "test-nonce-1234"
	method := "POST"
	path := "/api/v1/webhook"
	body := []byte(`{"event":"test"}`)

	// Compute a valid signature manually using the same algorithm as computeSignature.
	bodyHash := sha256.Sum256(body)
	bodyHashHex := hex.EncodeToString(bodyHash[:])
	canonical := strings.Join([]string{timestamp, nonce, strings.ToUpper(method), path, bodyHashHex}, "\n")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	sig := hex.EncodeToString(mac.Sum(nil))

	headers := map[string]string{
		HeaderKeyID:     keyID,
		HeaderTimestamp: timestamp,
		HeaderNonce:     nonce,
		HeaderSignature: sig,
	}

	err := validator.ValidateRequest(method, path, headers, body)
	if err == nil {
		t.Fatal("expected validation to fail for expired timestamp, but it succeeded")
	}
	if !strings.Contains(err.Error(), "timestamp skew") {
		t.Fatalf("expected timestamp skew error, got: %v", err)
	}
}

func TestInvalidSignature(t *testing.T) {
	secret := "test-secret-key"
	keyID := "key-1"

	signer := NewSigner(keyID, secret)
	validator := NewValidator(map[string]string{keyID: secret})

	headers, err := signer.SignRequest("POST", "/api/v1/webhook", []byte(`{"event":"test"}`))
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	// Corrupt the signature.
	headers[HeaderSignature] = "deadbeef" + headers[HeaderSignature][8:]

	err = validator.ValidateRequest("POST", "/api/v1/webhook", headers, []byte(`{"event":"test"}`))
	if err == nil {
		t.Fatal("expected validation to fail for corrupted signature, but it succeeded")
	}
	if !strings.Contains(err.Error(), "signature mismatch") {
		t.Fatalf("expected signature mismatch error, got: %v", err)
	}
}

func TestMissingHeaders(t *testing.T) {
	secret := "test-secret-key"
	keyID := "key-1"

	validator := NewValidator(map[string]string{keyID: secret})

	err := validator.ValidateRequest("POST", "/api/v1/webhook", map[string]string{}, []byte(`{}`))
	if err == nil {
		t.Fatal("expected validation to fail with empty headers, but it succeeded")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected 'missing' header error, got: %v", err)
	}
}

func TestUnknownKeyID(t *testing.T) {
	signerSecret := "signer-secret"
	validatorSecret := "validator-secret"

	signer := NewSigner("key-1", signerSecret)
	validator := NewValidator(map[string]string{"key-2": validatorSecret})

	headers, err := signer.SignRequest("GET", "/api/v1/status", nil)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	err = validator.ValidateRequest("GET", "/api/v1/status", headers, nil)
	if err == nil {
		t.Fatal("expected validation to fail for unknown key ID, but it succeeded")
	}
	if !strings.Contains(err.Error(), "unknown key ID") {
		t.Fatalf("expected 'unknown key ID' error, got: %v", err)
	}
}

func TestCrossCompatibility(t *testing.T) {
	secret := "cross-compat-secret" //nolint:gosec // test data
	keyID := "key-1"

	signer := NewSigner(keyID, secret)
	body := []byte(`{"action":"approve"}`)
	method := "POST"
	path := "/api/v1/approve"

	headers, err := signer.SignRequest(method, path, body)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	// Reconstruct the canonical string from the headers the signer produced,
	// using the same format the backend expects:
	// timestamp + "\n" + nonce + "\n" + METHOD + "\n" + path + "\n" + hex(sha256(body))
	timestamp := headers[HeaderTimestamp]
	nonce := headers[HeaderNonce]

	bodyHash := sha256.Sum256(body)
	bodyHashHex := hex.EncodeToString(bodyHash[:])

	canonical := strings.Join([]string{
		timestamp,
		nonce,
		strings.ToUpper(method),
		path,
		bodyHashHex,
	}, "\n")

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	actualSig := headers[HeaderSignature]
	if actualSig != expectedSig {
		t.Fatalf("signature mismatch:\n  got:      %s\n  expected: %s", actualSig, expectedSig)
	}
}

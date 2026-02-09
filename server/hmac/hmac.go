package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// nonceCleanupInterval controls how often stale nonces are evicted.
	// Cleanup runs lazily — at most once per this interval.
	nonceCleanupInterval = 1 * time.Minute
)

const (
	HeaderKeyID     = "X-JIT-KeyID"
	HeaderTimestamp = "X-JIT-Timestamp"
	HeaderNonce     = "X-JIT-Nonce"
	HeaderSignature = "X-JIT-Signature"

	// MaxTimestampSkew is the maximum allowed difference between the request
	// timestamp and the current time before the request is considered invalid.
	MaxTimestampSkew = 5 * time.Minute
)

// Signer produces HMAC-SHA256 signatures for outbound HTTP requests.
type Signer struct {
	KeyID  string
	Secret string
}

// NewSigner creates a new Signer with the given key ID and secret.
func NewSigner(keyID, secret string) *Signer {
	return &Signer{
		KeyID:  keyID,
		Secret: secret,
	}
}

// SignRequest generates HMAC authentication headers for an outbound request.
// The signature covers: timestamp + nonce + method + path + SHA256(body).
// It returns a map of HTTP headers to attach to the request.
func (s *Signer) SignRequest(method, path string, body []byte) (map[string]string, error) {
	if s.Secret == "" {
		return nil, fmt.Errorf("signing secret is not configured")
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := uuid.New().String()

	sig, err := computeSignature(s.Secret, timestamp, nonce, method, path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to compute signature: %w", err)
	}

	headers := map[string]string{
		HeaderKeyID:     s.KeyID,
		HeaderTimestamp: timestamp,
		HeaderNonce:     nonce,
		HeaderSignature: sig,
	}
	return headers, nil
}

// Validator validates HMAC-SHA256 signatures on inbound webhook requests.
type Validator struct {
	// Secrets maps key IDs to their corresponding secrets.
	Secrets map[string]string

	// seenMu protects seenNonces from concurrent access.
	seenMu sync.Mutex
	// seenNonces tracks previously seen nonces to prevent replay attacks (S2).
	// Keys are nonce strings; values are the time the nonce was first seen.
	seenNonces map[string]time.Time
	// lastCleanup tracks when stale nonces were last evicted.
	lastCleanup time.Time
}

// NewValidator creates a new Validator. The secrets map keys are key IDs and
// values are the corresponding HMAC secrets.
func NewValidator(secrets map[string]string) *Validator {
	return &Validator{
		Secrets:     secrets,
		seenNonces:  make(map[string]time.Time),
		lastCleanup: time.Now(),
	}
}

// ValidateRequest verifies the HMAC signature on an inbound request.
// headers must contain X-JIT-KeyID, X-JIT-Timestamp, X-JIT-Nonce, and
// X-JIT-Signature.
func (v *Validator) ValidateRequest(method, path string, headers map[string]string, body []byte) error {
	keyID := headers[HeaderKeyID]
	if keyID == "" {
		return fmt.Errorf("missing %s header", HeaderKeyID)
	}

	secret, ok := v.Secrets[keyID]
	if !ok {
		return fmt.Errorf("unknown key ID: %s", keyID)
	}

	timestamp := headers[HeaderTimestamp]
	if timestamp == "" {
		return fmt.Errorf("missing %s header", HeaderTimestamp)
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	skew := time.Since(time.Unix(ts, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxTimestampSkew {
		return fmt.Errorf("timestamp skew %v exceeds maximum %v", skew, MaxTimestampSkew)
	}

	nonce := headers[HeaderNonce]
	if nonce == "" {
		return fmt.Errorf("missing %s header", HeaderNonce)
	}

	providedSig := headers[HeaderSignature]
	if providedSig == "" {
		return fmt.Errorf("missing %s header", HeaderSignature)
	}

	expectedSig, err := computeSignature(secret, timestamp, nonce, method, path, body)
	if err != nil {
		return fmt.Errorf("failed to compute expected signature: %w", err)
	}

	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		return fmt.Errorf("signature mismatch")
	}

	// S2: Nonce replay protection — reject previously seen nonces.
	v.seenMu.Lock()
	defer v.seenMu.Unlock()

	if _, seen := v.seenNonces[nonce]; seen {
		return fmt.Errorf("replayed nonce: %s", nonce)
	}
	v.seenNonces[nonce] = time.Now()

	// Lazy cleanup: evict nonces older than MaxTimestampSkew.
	if time.Since(v.lastCleanup) > nonceCleanupInterval {
		cutoff := time.Now().Add(-MaxTimestampSkew)
		for k, t := range v.seenNonces {
			if t.Before(cutoff) {
				delete(v.seenNonces, k)
			}
		}
		v.lastCleanup = time.Now()
	}

	return nil
}

// computeSignature builds the canonical string and computes HMAC-SHA256.
// Canonical string: timestamp + "\n" + nonce + "\n" + METHOD + "\n" + path + "\n" + hex(SHA256(body))
func computeSignature(secret, timestamp, nonce, method, path string, body []byte) (string, error) {
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
	_, err := mac.Write([]byte(canonical))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(mac.Sum(nil)), nil
}

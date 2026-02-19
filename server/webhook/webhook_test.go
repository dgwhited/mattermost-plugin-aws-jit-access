package webhook

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/stretchr/testify/mock"

	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/api"
	jithmac "github.com/dgwhited/mattermost-plugin-aws-jit-access/server/hmac"
)

const (
	testKeyID  = "test-key"
	testSecret = "test-secret-value"
)

// testValidator returns an HMAC validator with a known test key.
func testValidator() *jithmac.Validator {
	return jithmac.NewValidator(map[string]string{testKeyID: testSecret})
}

// testSigner returns an HMAC signer with the same test key.
func testSigner() *jithmac.Signer {
	return jithmac.NewSigner(testKeyID, testSecret)
}

// makeSignedWebhookRequest creates a POST request with a valid HMAC signature.
func makeSignedWebhookRequest(t *testing.T, payload any) *http.Request {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	path := "/plugins/jit/webhook"
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))

	signer := testSigner()
	headers, err := signer.SignRequest(http.MethodPost, path, body)
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// ---------------------------------------------------------------------------
// ServeHTTP tests
// ---------------------------------------------------------------------------

func TestServeHTTP_MethodNotAllowed(t *testing.T) {
	mockAPI := &plugintest.API{}
	handler := NewHandler(mockAPI, nil)

	req := httptest.NewRequest(http.MethodGet, "/plugins/jit/webhook", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestServeHTTP_NilValidator(t *testing.T) {
	mockAPI := &plugintest.API{}
	mockAPI.On("LogError", mock.Anything).Return()
	handler := NewHandler(mockAPI, nil)

	req := httptest.NewRequest(http.MethodPost, "/plugins/jit/webhook", bytes.NewReader([]byte(`{}`)))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (fail-closed), got %d", rr.Code)
	}
	mockAPI.AssertCalled(t, "LogError", mock.Anything)
}

func TestServeHTTP_InvalidJSON(t *testing.T) {
	mockAPI := &plugintest.API{}
	mockAPI.On("LogError", mock.Anything, mock.Anything, mock.Anything).Return()
	handler := NewHandler(mockAPI, testValidator())

	// Send signed request with invalid JSON body.
	body := []byte("not json")
	path := "/plugins/jit/webhook"
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	signer := testSigner()
	headers, _ := signer.SignRequest(http.MethodPost, path, body)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestServeHTTP_MissingChannelID(t *testing.T) {
	mockAPI := &plugintest.API{}
	mockAPI.On("LogError", mock.Anything).Return()
	handler := NewHandler(mockAPI, testValidator())

	payload := api.WebhookPayload{
		RequestID: "req-1",
		Status:    "GRANTED",
		AccountID: "acct1",
	}
	req := makeSignedWebhookRequest(t, payload)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestServeHTTP_GrantedStatus(t *testing.T) {
	mockAPI := &plugintest.API{}
	mockAPI.On("CreatePost", mock.AnythingOfType("*model.Post")).Return(&model.Post{}, nil)
	handler := NewHandler(mockAPI, testValidator())

	payload := api.WebhookPayload{
		RequestID: "req-1",
		Status:    "GRANTED",
		AccountID: "acct1",
		ChannelID: "ch1",
		Actor:     "system",
		Details:   map[string]string{"requester_email": "user@test.com"},
	}
	req := makeSignedWebhookRequest(t, payload)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	mockAPI.AssertCalled(t, "CreatePost", mock.AnythingOfType("*model.Post"))

	// Verify the post was created in the right channel.
	call := mockAPI.Calls[0]
	post := call.Arguments[0].(*model.Post)
	if post.ChannelId != "ch1" {
		t.Errorf("expected ChannelId ch1, got %s", post.ChannelId)
	}
}

func TestServeHTTP_RevokedStatus(t *testing.T) {
	mockAPI := &plugintest.API{}
	mockAPI.On("CreatePost", mock.AnythingOfType("*model.Post")).Return(&model.Post{}, nil)
	handler := NewHandler(mockAPI, testValidator())

	payload := api.WebhookPayload{
		RequestID: "req-1",
		Status:    "REVOKED",
		AccountID: "acct1",
		ChannelID: "ch1",
		Actor:     "admin@test.com",
	}
	req := makeSignedWebhookRequest(t, payload)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	mockAPI.AssertCalled(t, "CreatePost", mock.AnythingOfType("*model.Post"))
}

func TestServeHTTP_ExpiredStatus(t *testing.T) {
	mockAPI := &plugintest.API{}
	mockAPI.On("CreatePost", mock.AnythingOfType("*model.Post")).Return(&model.Post{}, nil)
	handler := NewHandler(mockAPI, testValidator())

	payload := api.WebhookPayload{
		RequestID: "req-1",
		Status:    "EXPIRED",
		AccountID: "acct1",
		ChannelID: "ch1",
	}
	req := makeSignedWebhookRequest(t, payload)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestServeHTTP_DeniedStatus(t *testing.T) {
	mockAPI := &plugintest.API{}
	mockAPI.On("CreatePost", mock.AnythingOfType("*model.Post")).Return(&model.Post{}, nil)
	handler := NewHandler(mockAPI, testValidator())

	payload := api.WebhookPayload{
		RequestID: "req-1",
		Status:    "DENIED",
		AccountID: "acct1",
		ChannelID: "ch1",
		Actor:     "approver@test.com",
	}
	req := makeSignedWebhookRequest(t, payload)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestServeHTTP_ErrorStatus(t *testing.T) {
	mockAPI := &plugintest.API{}
	mockAPI.On("CreatePost", mock.AnythingOfType("*model.Post")).Return(&model.Post{}, nil)
	handler := NewHandler(mockAPI, testValidator())

	payload := api.WebhookPayload{
		RequestID: "req-1",
		Status:    "ERROR",
		AccountID: "acct1",
		ChannelID: "ch1",
		Details:   map[string]string{"error": "grant failed"},
	}
	req := makeSignedWebhookRequest(t, payload)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestServeHTTP_UnknownStatus(t *testing.T) {
	mockAPI := &plugintest.API{}
	mockAPI.On("LogWarn", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()
	handler := NewHandler(mockAPI, testValidator())

	payload := api.WebhookPayload{
		RequestID: "req-1",
		Status:    "UNKNOWN",
		AccountID: "acct1",
		ChannelID: "ch1",
	}
	req := makeSignedWebhookRequest(t, payload)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// detailsToString tests
// ---------------------------------------------------------------------------

func TestDetailsToString_Empty(t *testing.T) {
	if got := detailsToString(nil); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestDetailsToString_WithEntries(t *testing.T) {
	details := map[string]string{"error": "failed", "phase": "grant"}
	result := detailsToString(details)
	if result == "" {
		t.Error("expected non-empty string")
	}
}

func TestDetailsToString_SingleEntry(t *testing.T) {
	details := map[string]string{"key": "value"}
	result := detailsToString(details)
	if result != "key: value" {
		t.Errorf("expected 'key: value', got %q", result)
	}
}

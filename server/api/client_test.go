package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer creates an httptest.Server and a Client pointing to it.
// No HMAC signer is attached (signer=nil) so requests are unsigned.
func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	server := httptest.NewServer(handler)
	client := &Client{
		BaseURL:    server.URL,
		Signer:     nil,
		HTTPClient: server.Client(),
	}
	return server, client
}

// ---------------------------------------------------------------------------
// CreateRequest tests
// ---------------------------------------------------------------------------

func TestCreateRequest_Success(t *testing.T) {
	server, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/requests" {
			t.Errorf("expected /requests, got %s", r.URL.Path)
		}

		body, _ := io.ReadAll(r.Body)
		var input CreateRequestInput
		if err := json.Unmarshal(body, &input); err != nil {
			t.Errorf("invalid body: %v", err)
		}
		if input.AccountID != "acct1" {
			t.Errorf("expected acct1, got %s", input.AccountID)
		}

		resp := JitRequest{
			RequestID: "req-1",
			AccountID: "acct1",
			Status:    "PENDING",
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer server.Close()

	req, err := client.CreateRequest(context.Background(), CreateRequestInput{
		AccountID:                "acct1",
		ChannelID:                "ch1",
		RequesterMMUserID:        "user1",
		RequesterEmail:           "user@test.com",
		Reason:                   "test",
		RequestedDurationMinutes: 60,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.RequestID != "req-1" {
		t.Errorf("expected req-1, got %s", req.RequestID)
	}
	if req.Status != "PENDING" {
		t.Errorf("expected PENDING, got %s", req.Status)
	}
}

func TestCreateRequest_BackendError(t *testing.T) {
	server, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "missing fields"})
	})
	defer server.Close()

	_, err := client.CreateRequest(context.Background(), CreateRequestInput{})
	if err == nil {
		t.Fatal("expected error from backend")
	}
}

// ---------------------------------------------------------------------------
// ApproveRequest tests
// ---------------------------------------------------------------------------

func TestApproveRequest_Success(t *testing.T) {
	server, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/requests/req-1/approve" {
			t.Errorf("expected /requests/req-1/approve, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	err := client.ApproveRequest(context.Background(), "req-1", ApproveRequestInput{
		ApproverMMUserID: "approver1",
		ApproverEmail:    "approver@test.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApproveRequest_Error(t *testing.T) {
	server, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "request not found"})
	})
	defer server.Close()

	err := client.ApproveRequest(context.Background(), "nonexistent", ApproveRequestInput{
		ApproverMMUserID: "approver1",
		ApproverEmail:    "approver@test.com",
	})
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

// ---------------------------------------------------------------------------
// DenyRequest tests
// ---------------------------------------------------------------------------

func TestDenyRequest_Success(t *testing.T) {
	server, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/requests/req-1/deny" {
			t.Errorf("expected /requests/req-1/deny, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	err := client.DenyRequest(context.Background(), "req-1", DenyRequestInput{
		DenierMMUserID: "denier1",
		DenierEmail:    "denier@test.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RevokeRequest tests
// ---------------------------------------------------------------------------

func TestRevokeRequest_Success(t *testing.T) {
	server, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/requests/req-1/revoke" {
			t.Errorf("expected /requests/req-1/revoke, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	err := client.RevokeRequest(context.Background(), "req-1", RevokeRequestInput{
		ActorMMUserID: "admin1",
		ActorEmail:    "admin@test.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListRequests tests
// ---------------------------------------------------------------------------

func TestListRequests_Success(t *testing.T) {
	server, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Query().Get("channel_id") != "ch1" {
			t.Errorf("expected channel_id=ch1, got %s", r.URL.Query().Get("channel_id"))
		}

		resp := ReportingResponse{
			Items: []JitRequest{
				{RequestID: "req-1", Status: "GRANTED"},
				{RequestID: "req-2", Status: "PENDING"},
			},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer server.Close()

	resp, err := client.ListRequests(context.Background(), map[string]string{"channel_id": "ch1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Errorf("expected 2 items, got %d", len(resp.Items))
	}
}

func TestListRequests_NoParams(t *testing.T) {
	server, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("expected no query params, got %s", r.URL.RawQuery)
		}
		resp := ReportingResponse{Items: []JitRequest{}}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer server.Close()

	resp, err := client.ListRequests(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Items == nil {
		t.Error("expected non-nil items")
	}
}

// ---------------------------------------------------------------------------
// BindAccount tests
// ---------------------------------------------------------------------------

func TestBindAccount_Success(t *testing.T) {
	server, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/config/bind" {
			t.Errorf("unexpected method/path: %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var input BindAccountInput
		_ = json.Unmarshal(body, &input)
		if input.ChannelID != "ch1" || input.AccountID != "acct1" {
			t.Errorf("unexpected input: %+v", input)
		}
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	err := client.BindAccount(context.Background(), "ch1", "acct1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SetApprovers tests
// ---------------------------------------------------------------------------

func TestSetApprovers_Success(t *testing.T) {
	server, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/config/approvers" {
			t.Errorf("unexpected method/path: %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var input SetApproversInput
		_ = json.Unmarshal(body, &input)
		if len(input.ApproverIDs) != 2 {
			t.Errorf("expected 2 approver IDs, got %d", len(input.ApproverIDs))
		}
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	err := client.SetApprovers(context.Background(), "ch1", []string{"u1", "u2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetBoundAccounts tests
// ---------------------------------------------------------------------------

func TestGetBoundAccounts_Success(t *testing.T) {
	server, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Query().Get("channel_id") != "ch1" {
			t.Errorf("expected channel_id=ch1")
		}
		configs := []JitConfig{
			{ChannelID: "ch1", AccountID: "acct1", MaxRequestHours: 4},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(configs)
	})
	defer server.Close()

	configs, err := client.GetBoundAccounts(context.Background(), "ch1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Errorf("expected 1 config, got %d", len(configs))
	}
	if configs[0].MaxRequestHours != 4 {
		t.Errorf("expected max_request_hours 4, got %d", configs[0].MaxRequestHours)
	}
}

func TestGetBoundAccounts_ServerError(t *testing.T) {
	server, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"internal error"}`))
	})
	defer server.Close()

	_, err := client.GetBoundAccounts(context.Background(), "ch1")
	if err == nil {
		t.Fatal("expected error from server error")
	}
}

// ---------------------------------------------------------------------------
// readErrorResponse tests
// ---------------------------------------------------------------------------

func TestReadErrorResponse_WithMessage(t *testing.T) {
	resp := &http.Response{
		StatusCode: 400,
		Body:       io.NopCloser(jsonReader(t, map[string]string{"message": "bad request"})),
	}
	err := readErrorResponse(resp)
	if err == nil {
		t.Fatal("expected error")
	}
	// Should contain the message from the body.
	if got := err.Error(); got != "backend error (HTTP 400): bad request" {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestReadErrorResponse_PlainText(t *testing.T) {
	resp := &http.Response{
		StatusCode: 500,
		Body:       io.NopCloser(jsonReader(t, "not json")),
	}
	err := readErrorResponse(resp)
	if err == nil {
		t.Fatal("expected error")
	}
}

func jsonReader(t *testing.T, v any) io.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return io.NopCloser(bytesReader(b))
}

type bytesReaderWrapper struct {
	data []byte
	pos  int
}

func (r *bytesReaderWrapper) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func bytesReader(b []byte) *bytesReaderWrapper {
	return &bytesReaderWrapper{data: b}
}

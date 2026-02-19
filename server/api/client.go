package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	jithmac "github.com/dgwhited/mattermost-plugin-aws-jit-access/server/hmac"
)

// ---------- Model types matching the backend ----------

// JitRequest represents an access request in the backend.
// Field names match the backend's models.JitRequest exactly.
type JitRequest struct {
	RequestID                string `json:"request_id"`
	AccountID                string `json:"account_id"`
	ChannelID                string `json:"channel_id"`
	RequesterMMUserID        string `json:"requester_mm_user_id"`
	RequesterEmail           string `json:"requester_email"`
	Jira                     string `json:"jira,omitempty"`
	Reason                   string `json:"reason"`
	RequestedDurationMinutes int    `json:"requested_duration_minutes"`
	Status                   string `json:"status"`
	CreatedAt                string `json:"created_at"`
	ApprovedAt               string `json:"approved_at,omitempty"`
	DeniedAt                 string `json:"denied_at,omitempty"`
	GrantTime                string `json:"grant_time,omitempty"`
	RevokedAt                string `json:"revoked_at,omitempty"`
	ExpiredAt                string `json:"expired_at,omitempty"`
	EndTime                  string `json:"end_time"`
	ApproverMMUserID         string `json:"approver_mm_user_id,omitempty"`
	ApproverEmail            string `json:"approver_email,omitempty"`
	IdentityStoreUserID      string `json:"identity_store_user_id,omitempty"`
	AssignmentStatus         string `json:"assignment_status,omitempty"`
	ErrorDetails             string `json:"error_details,omitempty"`
}

// JitConfig represents a channel-to-account binding and its approvers.
type JitConfig struct {
	ChannelID              string   `json:"channel_id"`
	AccountID              string   `json:"account_id"`
	ApproverMMUserIDs      []string `json:"approver_mm_user_ids,omitempty"`
	ApprovalPolicy         string   `json:"approval_policy,omitempty"`
	AllowSelfApproval      bool     `json:"allow_self_approval,omitempty"`
	MaxRequestHours        int      `json:"max_request_hours,omitempty"`
	SessionDurationMinutes int      `json:"session_duration_minutes,omitempty"`
	UpdatedAt              string   `json:"updated_at,omitempty"`
}

// WebhookPayload is the payload sent by the backend to the plugin webhook.
type WebhookPayload struct {
	RequestID string            `json:"request_id"`
	Status    string            `json:"status"`
	AccountID string            `json:"account_id"`
	ChannelID string            `json:"channel_id"`
	Actor     string            `json:"actor,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
}

// ReportingResponse is the response from the GET /requests endpoint.
type ReportingResponse struct {
	Items     []JitRequest      `json:"items"`
	NextToken string            `json:"next_token,omitempty"`
	Filters   map[string]string `json:"filters,omitempty"`
}

// CreateRequestInput is the payload for POST /requests.
type CreateRequestInput struct {
	AccountID                string `json:"account_id"`
	ChannelID                string `json:"channel_id"`
	RequesterMMUserID        string `json:"requester_mm_user_id"`
	RequesterEmail           string `json:"requester_email"`
	Jira                     string `json:"jira,omitempty"`
	Reason                   string `json:"reason"`
	RequestedDurationMinutes int    `json:"requested_duration_minutes"`
}

// ApproveRequestInput is the payload for POST /requests/{id}/approve.
type ApproveRequestInput struct {
	ApproverMMUserID string `json:"approver_mm_user_id"`
	ApproverEmail    string `json:"approver_email"`
}

// DenyRequestInput is the payload for POST /requests/{id}/deny.
type DenyRequestInput struct {
	DenierMMUserID string `json:"denier_mm_user_id"`
	DenierEmail    string `json:"denier_email"`
	Reason         string `json:"reason,omitempty"`
}

// RevokeRequestInput is the payload for POST /requests/{id}/revoke.
type RevokeRequestInput struct {
	ActorMMUserID string `json:"actor_mm_user_id"`
	ActorEmail    string `json:"actor_email"`
}

// BindAccountInput is the payload for POST /config/bind.
type BindAccountInput struct {
	ChannelID string `json:"channel_id"`
	AccountID string `json:"account_id"`
}

// SetApproversInput is the payload for POST /config/approvers.
type SetApproversInput struct {
	ChannelID   string   `json:"channel_id"`
	ApproverIDs []string `json:"approver_ids"`
}

// ---------- Client ----------

// Client communicates with the JIT backend API.
type Client struct {
	BaseURL    string
	Signer     *jithmac.Signer
	HTTPClient *http.Client
}

// NewClient creates a new backend API client.
func NewClient(baseURL string, signer *jithmac.Signer) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Signer:  signer,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CreateRequest submits a new JIT access request.
func (c *Client) CreateRequest(ctx context.Context, input CreateRequestInput) (*JitRequest, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/requests", body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, readErrorResponse(resp)
	}

	var result JitRequest
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}

// ApproveRequest approves a pending access request.
func (c *Client) ApproveRequest(ctx context.Context, requestID string, input ApproveRequestInput) error {
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	path := fmt.Sprintf("/requests/%s/approve", url.PathEscape(requestID))
	resp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return readErrorResponse(resp)
	}
	return nil
}

// DenyRequest denies a pending access request.
func (c *Client) DenyRequest(ctx context.Context, requestID string, input DenyRequestInput) error {
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	path := fmt.Sprintf("/requests/%s/deny", url.PathEscape(requestID))
	resp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return readErrorResponse(resp)
	}
	return nil
}

// RevokeRequest force-revokes an active access request.
func (c *Client) RevokeRequest(ctx context.Context, requestID string, input RevokeRequestInput) error {
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	path := fmt.Sprintf("/requests/%s/revoke", url.PathEscape(requestID))
	resp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return readErrorResponse(resp)
	}
	return nil
}

// GetRequest fetches a single JIT request by ID.
func (c *Client) GetRequest(ctx context.Context, requestID string) (*JitRequest, error) {
	path := fmt.Sprintf("/requests/%s", url.PathEscape(requestID))

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("request %s not found", requestID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, readErrorResponse(resp)
	}

	var result JitRequest
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}

// ListRequests queries requests, optionally filtering by request ID.
func (c *Client) ListRequests(ctx context.Context, params map[string]string) (*ReportingResponse, error) {
	path := "/requests"
	if len(params) > 0 {
		q := url.Values{}
		for k, v := range params {
			q.Set(k, v)
		}
		path = path + "?" + q.Encode()
	}

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, readErrorResponse(resp)
	}

	var result ReportingResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}

// BindAccount binds an AWS account to a Mattermost channel.
func (c *Client) BindAccount(ctx context.Context, channelID, accountID string) error {
	input := BindAccountInput{
		ChannelID: channelID,
		AccountID: accountID,
	}
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/config/bind", body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return readErrorResponse(resp)
	}
	return nil
}

// SetApprovers sets the approvers for the accounts bound to a channel.
func (c *Client) SetApprovers(ctx context.Context, channelID string, approverIDs []string) error {
	input := SetApproversInput{
		ChannelID:   channelID,
		ApproverIDs: approverIDs,
	}
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/config/approvers", body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return readErrorResponse(resp)
	}
	return nil
}

// GetBoundAccounts returns the accounts bound to a channel.
func (c *Client) GetBoundAccounts(ctx context.Context, channelID string) ([]JitConfig, error) {
	path := fmt.Sprintf("/config/accounts?channel_id=%s", url.QueryEscape(channelID))

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, readErrorResponse(resp)
	}

	var configs []JitConfig
	if err := json.NewDecoder(resp.Body).Decode(&configs); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return configs, nil
}

// ---------- Helpers ----------

func (c *Client) doRequest(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	fullURL := c.BaseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if c.Signer != nil {
		if body == nil {
			body = []byte{}
		}
		// Sign using only the path portion (no query string), because API Gateway V2
		// separates path from query params and the backend's ValidateRequest receives
		// only event.RequestContext.HTTP.Path (which never includes the query string).
		signPath, _, _ := strings.Cut(path, "?")
		var headers map[string]string
		headers, err = c.Signer.SignRequest(method, signPath, body)
		if err != nil {
			return nil, fmt.Errorf("sign request: %w", err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute HTTP request: %w", err)
	}
	return resp, nil
}

// apiError is a standard error envelope from the backend.
type apiError struct {
	Message string `json:"message"`
}

func readErrorResponse(resp *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("backend returned status %d and failed to read body: %w", resp.StatusCode, err)
	}

	var apiErr apiError
	if json.Unmarshal(body, &apiErr) == nil && apiErr.Message != "" {
		return fmt.Errorf("backend error (HTTP %d): %s", resp.StatusCode, apiErr.Message)
	}

	return fmt.Errorf("backend returned HTTP %d: %s", resp.StatusCode, string(body))
}

package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"

	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/api"
)

// StatusHandler handles the /jit status command.
type StatusHandler struct {
	api    plugin.API
	client *api.Client
}

// NewStatusHandler creates a new StatusHandler.
func NewStatusHandler(api plugin.API, client *api.Client) *StatusHandler {
	return &StatusHandler{
		api:    api,
		client: client,
	}
}

// HandleStatus queries the backend for request status and displays the result.
func (h *StatusHandler) HandleStatus(args *model.CommandArgs, requestID string) (*model.CommandResponse, *model.AppError) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	params := make(map[string]string)
	if requestID != "" {
		params["request_id"] = requestID
	} else {
		params["channel_id"] = args.ChannelId
	}

	resp, err := h.client.ListRequests(ctx, params)
	if err != nil {
		return ephemeralResponse(h.api, args,
			fmt.Sprintf("Failed to query request status: %s", err.Error())), nil
	}

	if len(resp.Items) == 0 {
		msg := "No requests found."
		if requestID != "" {
			msg = fmt.Sprintf("No request found with ID `%s`.", requestID)
		}
		return ephemeralResponse(h.api, args, msg), nil
	}

	var sb strings.Builder
	sb.WriteString("### JIT Request Status\n\n")
	sb.WriteString("| Request ID | Account | Status | Duration | Created |\n")
	sb.WriteString("|------------|---------|--------|----------|---------|\n")

	for _, req := range resp.Items {
		statusEmoji := statusToEmoji(req.Status)
		sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s %s | %d min | %s |\n",
			truncateID(req.RequestID), req.AccountID, statusEmoji, req.Status,
			req.RequestedDurationMinutes, req.CreatedAt))
	}

	if requestID != "" && len(resp.Items) == 1 {
		req := resp.Items[0]
		sb.WriteString("\n**Details:**\n")
		sb.WriteString(fmt.Sprintf("- **Reason:** %s\n", req.Reason))
		if req.Jira != "" {
			sb.WriteString(fmt.Sprintf("- **Jira:** %s\n", req.Jira))
		}
		if req.ApproverEmail != "" {
			sb.WriteString(fmt.Sprintf("- **Approved by:** %s\n", req.ApproverEmail))
		}
		if req.EndTime != "" {
			sb.WriteString(fmt.Sprintf("- **End time:** %s\n", req.EndTime))
		}
		if req.ErrorDetails != "" {
			sb.WriteString(fmt.Sprintf("- **Error:** %s\n", req.ErrorDetails))
		}
	}

	return ephemeralResponse(h.api, args, sb.String()), nil
}

// statusToEmoji returns a markdown emoji for a given status string.
func statusToEmoji(status string) string {
	switch strings.ToUpper(status) {
	case "PENDING":
		return ":hourglass:"
	case "APPROVED":
		return ":ballot_box_with_check:"
	case "GRANTED":
		return ":white_check_mark:"
	case "DENIED":
		return ":no_entry_sign:"
	case "REVOKED":
		return ":rotating_light:"
	case "EXPIRED":
		return ":clock4:"
	case "ERROR":
		return ":x:"
	default:
		return ":question:"
	}
}

// truncateID returns the first 8 characters of an ID for display purposes.
func truncateID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

package commands

import (
	"context"
	"fmt"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"

	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/api"
)

// RevokeHandler handles the /jit revoke command.
type RevokeHandler struct {
	api    plugin.API
	client *api.Client
}

// NewRevokeHandler creates a new RevokeHandler.
func NewRevokeHandler(api plugin.API, client *api.Client) *RevokeHandler {
	return &RevokeHandler{
		api:    api,
		client: client,
	}
}

// HandleRevoke revokes a JIT access request by ID.
// Users can revoke their own active requests. Admins can revoke anyone's.
// Returns immediately with an ephemeral acknowledgement, then processes
// the revocation asynchronously so the command input clears instantly.
func (h *RevokeHandler) HandleRevoke(args *model.CommandArgs, requestID string, isAdmin bool) (*model.CommandResponse, *model.AppError) {
	if requestID == "" {
		return ephemeralResponse(h.api, args, "Usage: `/jit revoke <request_id>`"), nil
	}

	// Return immediately so the command input clears.
	// The actual work happens in the goroutine below.
	go h.doRevoke(args, requestID, isAdmin)

	return &model.CommandResponse{}, nil
}

// doRevoke performs the actual revoke operation asynchronously.
func (h *RevokeHandler) doRevoke(args *model.CommandArgs, requestID string, isAdmin bool) {
	user, appErr := h.api.GetUser(args.UserId)
	if appErr != nil {
		h.sendEphemeral(args, "Failed to identify user.")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Fetch the request to check ownership and current status.
	jitReq, err := h.client.GetRequest(ctx, requestID)
	if err != nil {
		h.sendEphemeral(args, fmt.Sprintf("Request `%s` not found.", requestID))
		return
	}

	isSelfRevoke := jitReq.RequesterMMUserID == args.UserId

	if !isSelfRevoke && !isAdmin {
		h.sendEphemeral(args, "You can only revoke your own requests. Contact an admin to revoke other users' requests.")
		return
	}

	// Check status and give a friendly message if it can't be revoked.
	if jitReq.Status != "GRANTED" {
		h.sendEphemeral(args, friendlyStatusMessage(requestID, jitReq.Status))
		return
	}

	input := api.RevokeRequestInput{
		ActorMMUserID: args.UserId,
		ActorEmail:    user.Email,
	}

	if err := h.client.RevokeRequest(ctx, requestID, input); err != nil {
		h.sendEphemeral(args, fmt.Sprintf("Failed to revoke request `%s`: %s", requestID, err.Error()))
		return
	}

	// Post confirmation in the channel.
	var message string
	if isSelfRevoke {
		message = fmt.Sprintf(":rotating_light: Request `%s` has been **revoked** by the requester @%s.", requestID, user.Username)
	} else {
		message = fmt.Sprintf(":rotating_light: Request `%s` has been **force-revoked** by an administrator.", requestID)
	}

	_, _ = h.api.CreatePost(&model.Post{
		UserId:    args.UserId,
		ChannelId: args.ChannelId,
		Message:   message,
	})
}

// sendEphemeral posts an ephemeral message visible only to the command invoker.
func (h *RevokeHandler) sendEphemeral(args *model.CommandArgs, message string) {
	h.api.SendEphemeralPost(args.UserId, &model.Post{
		UserId:    args.UserId,
		ChannelId: args.ChannelId,
		Message:   message,
	})
}

// friendlyStatusMessage returns a human-friendly message explaining why a
// request in the given status cannot be revoked.
func friendlyStatusMessage(requestID, status string) string {
	switch status {
	case "EXPIRED":
		return fmt.Sprintf("Request `%s` has already **expired** — access was automatically removed when the timer ended.", requestID)
	case "REVOKED":
		return fmt.Sprintf("Request `%s` has already been **revoked**.", requestID)
	case "DENIED":
		return fmt.Sprintf("Request `%s` was **denied** and access was never granted.", requestID)
	case "PENDING":
		return fmt.Sprintf("Request `%s` is still **pending approval** — there is no active access to revoke.", requestID)
	case "APPROVED":
		return fmt.Sprintf("Request `%s` has been **approved** but access is still being provisioned. Try again in a moment.", requestID)
	case "ERROR":
		return fmt.Sprintf("Request `%s` is in an **error** state. Contact an administrator.", requestID)
	default:
		return fmt.Sprintf("Request `%s` is in status **%s** and cannot be revoked.", requestID, status)
	}
}

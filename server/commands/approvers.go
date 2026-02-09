package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"

	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/api"
)

// ApproversHandler handles the /jit approvers command.
type ApproversHandler struct {
	api    plugin.API
	client *api.Client
}

// NewApproversHandler creates a new ApproversHandler.
func NewApproversHandler(api plugin.API, client *api.Client) *ApproversHandler {
	return &ApproversHandler{
		api:    api,
		client: client,
	}
}

// HandleApprovers resolves the given @usernames to Mattermost user IDs and
// sets them as approvers for the accounts bound to this channel.
func (h *ApproversHandler) HandleApprovers(args *model.CommandArgs, usernames []string) (*model.CommandResponse, *model.AppError) {
	if len(usernames) == 0 {
		return ephemeralResponse(h.api, args, "Usage: `/jit approvers @user1 @user2 ...`"), nil
	}

	// Resolve each @username to a Mattermost user ID.
	var approverIDs []string
	var resolvedNames []string
	for _, raw := range usernames {
		username := strings.TrimPrefix(raw, "@")
		if username == "" {
			continue
		}

		user, appErr := h.api.GetUserByUsername(username)
		if appErr != nil {
			return ephemeralResponse(h.api, args,
				fmt.Sprintf("Could not find user `@%s`: %s", username, appErr.Message)), nil
		}

		approverIDs = append(approverIDs, user.Id)
		resolvedNames = append(resolvedNames, "@"+user.Username)
	}

	if len(approverIDs) == 0 {
		return ephemeralResponse(h.api, args, "No valid usernames provided. Usage: `/jit approvers @user1 @user2 ...`"), nil
	}

	// Call the backend to update approvers.
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	if err := h.client.SetApprovers(ctx, args.ChannelId, approverIDs); err != nil {
		return ephemeralResponse(h.api, args,
			fmt.Sprintf("Failed to set approvers: %s", err.Error())), nil
	}

	// Post a visible confirmation in the channel.
	confirmPost := &model.Post{
		UserId:    args.UserId,
		ChannelId: args.ChannelId,
		Message: fmt.Sprintf(":white_check_mark: Approvers for this channel have been set to: %s",
			strings.Join(resolvedNames, ", ")),
	}
	h.api.CreatePost(confirmPost)

	return &model.CommandResponse{}, nil
}

package commands

import (
	"context"
	"fmt"
	"regexp"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"

	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/api"
)

// awsAccountIDRegex validates a 12-digit AWS account ID.
var awsAccountIDRegex = regexp.MustCompile(`^\d{12}$`)

// BindHandler handles the /jit bind command.
type BindHandler struct {
	api    plugin.API
	client *api.Client
}

// NewBindHandler creates a new BindHandler.
func NewBindHandler(api plugin.API, client *api.Client) *BindHandler {
	return &BindHandler{
		api:    api,
		client: client,
	}
}

// HandleBind binds an AWS account ID to the current Mattermost channel.
func (h *BindHandler) HandleBind(args *model.CommandArgs, accountID string) (*model.CommandResponse, *model.AppError) {
	// Validate the account ID format.
	if !awsAccountIDRegex.MatchString(accountID) {
		return ephemeralResponse(h.api, args,
			fmt.Sprintf("Invalid AWS account ID `%s`. Account IDs must be exactly 12 digits.", accountID)), nil
	}

	// Call the backend to create the binding.
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	if err := h.client.BindAccount(ctx, args.ChannelId, accountID); err != nil {
		return ephemeralResponse(h.api, args,
			fmt.Sprintf("Failed to bind account: %s", err.Error())), nil
	}

	// Post a visible confirmation in the channel.
	confirmPost := &model.Post{
		UserId:    args.UserId,
		ChannelId: args.ChannelId,
		Message:   fmt.Sprintf(":white_check_mark: AWS account `%s` has been bound to this channel.", accountID),
	}
	h.api.CreatePost(confirmPost)

	return &model.CommandResponse{}, nil
}

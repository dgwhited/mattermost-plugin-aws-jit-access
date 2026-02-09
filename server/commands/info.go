package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"

	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/api"
)

// InfoHandler handles the /jit info command.
type InfoHandler struct {
	api    plugin.API
	client *api.Client
}

// NewInfoHandler creates a new InfoHandler.
func NewInfoHandler(api plugin.API, client *api.Client) *InfoHandler {
	return &InfoHandler{
		api:    api,
		client: client,
	}
}

// HandleInfo displays the channel's bound accounts and their approvers.
func (h *InfoHandler) HandleInfo(args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	configs, err := h.client.GetBoundAccounts(ctx, args.ChannelId)
	if err != nil {
		return ephemeralResponse(h.api, args,
			fmt.Sprintf("Failed to fetch channel configuration: %s", err.Error())), nil
	}

	if len(configs) == 0 {
		return ephemeralResponse(h.api, args,
			"No AWS accounts are bound to this channel.\nAn admin can bind one with `/jit bind <account_id>`."), nil
	}

	var sb strings.Builder
	sb.WriteString("### JIT Access — Channel Configuration\n\n")
	sb.WriteString("| AWS Account | Approvers | Max Duration | Self-Approve |\n")
	sb.WriteString("|:------------|:----------|:-------------|:-------------|\n")

	for _, cfg := range configs {
		approvers := h.resolveApprovers(cfg.ApproverMMUserIDs)
		maxDuration := "—"
		if cfg.MaxRequestHours > 0 {
			maxDuration = fmt.Sprintf("%d hours", cfg.MaxRequestHours)
		}
		selfApprove := "No"
		if cfg.AllowSelfApproval {
			selfApprove = "Yes"
		}

		sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s |\n",
			cfg.AccountID, approvers, maxDuration, selfApprove))
	}

	sb.WriteString("\n_Use `/jit request` to request access._")

	return ephemeralResponse(h.api, args, sb.String()), nil
}

// resolveApprovers converts a list of Mattermost user IDs to @username mentions.
func (h *InfoHandler) resolveApprovers(userIDs []string) string {
	if len(userIDs) == 0 {
		return "_none configured_"
	}

	names := make([]string, 0, len(userIDs))
	for _, id := range userIDs {
		user, appErr := h.api.GetUser(id)
		if appErr != nil {
			names = append(names, fmt.Sprintf("`%s`", truncateID(id)))
			continue
		}
		names = append(names, fmt.Sprintf("@%s", user.Username))
	}
	return strings.Join(names, ", ")
}

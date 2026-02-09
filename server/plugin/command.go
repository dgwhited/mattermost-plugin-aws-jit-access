package plugin

import (
	"fmt"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
	mmPlugin "github.com/mattermost/mattermost/server/public/plugin"

	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/commands"
)

const (
	commandTrigger = "jit"
)

// ExecuteCommand handles the /jit slash command and its subcommands.
func (p *Plugin) ExecuteCommand(_ *mmPlugin.Context, args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	parts := strings.Fields(args.Command)
	if len(parts) < 2 {
		return p.handleHelp(args)
	}

	subcommand := strings.ToLower(parts[1])

	switch subcommand {
	case "request":
		return p.handleRequest(args)
	case "bind":
		return p.handleBind(args, parts)
	case "approvers":
		return p.handleApprovers(args, parts)
	case "revoke":
		return p.handleRevoke(args, parts)
	case "status":
		return p.handleStatus(args, parts)
	case "info":
		return p.handleInfo(args)
	case "help":
		return p.handleHelp(args)
	default:
		return p.ephemeral(args, fmt.Sprintf("Unknown subcommand `%s`. Use `/jit help` for available commands.", subcommand)), nil
	}
}

// handleRequest opens the interactive dialog for creating a JIT request.
func (p *Plugin) handleRequest(args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	client := p.getAPIClient()
	if client == nil {
		return p.ephemeral(args, "Plugin is not fully configured. Please ask an admin to set the Backend API URL and signing keys."), nil
	}

	handler := commands.NewRequestHandler(p.API, client)
	return handler.HandleRequestCommand(args)
}

// handleBind handles `/jit bind <account_id>`.
func (p *Plugin) handleBind(args *model.CommandArgs, parts []string) (*model.CommandResponse, *model.AppError) {
	if !p.isSystemAdmin(args.UserId) {
		return p.ephemeral(args, "Only system administrators can bind AWS accounts to channels."), nil
	}

	if len(parts) < 3 {
		return p.ephemeral(args, "Usage: `/jit bind <account_id>`"), nil
	}

	client := p.getAPIClient()
	if client == nil {
		return p.ephemeral(args, "Plugin is not fully configured. Please ask an admin to set the Backend API URL and signing keys."), nil
	}

	accountID := parts[2]
	handler := commands.NewBindHandler(p.API, client)
	return handler.HandleBind(args, accountID)
}

// handleApprovers handles `/jit approvers @user1 @user2 ...`.
func (p *Plugin) handleApprovers(args *model.CommandArgs, parts []string) (*model.CommandResponse, *model.AppError) {
	if !p.isSystemAdmin(args.UserId) {
		return p.ephemeral(args, "Only system administrators can set approvers."), nil
	}

	if len(parts) < 3 {
		return p.ephemeral(args, "Usage: `/jit approvers @user1 @user2 ...`"), nil
	}

	client := p.getAPIClient()
	if client == nil {
		return p.ephemeral(args, "Plugin is not fully configured. Please ask an admin to set the Backend API URL and signing keys."), nil
	}

	usernames := parts[2:]
	handler := commands.NewApproversHandler(p.API, client)
	return handler.HandleApprovers(args, usernames)
}

// handleRevoke handles `/jit revoke <request_id>`.
// Users can revoke their own active requests. Admins can revoke anyone's.
func (p *Plugin) handleRevoke(args *model.CommandArgs, parts []string) (*model.CommandResponse, *model.AppError) {
	if len(parts) < 3 {
		return p.ephemeral(args, "Usage: `/jit revoke <request_id>`"), nil
	}

	client := p.getAPIClient()
	if client == nil {
		return p.ephemeral(args, "Plugin is not fully configured. Please ask an admin to set the Backend API URL and signing keys."), nil
	}

	requestID := parts[2]
	isAdmin := p.isSystemAdmin(args.UserId)
	handler := commands.NewRevokeHandler(p.API, client)
	return handler.HandleRevoke(args, requestID, isAdmin)
}

// handleStatus handles `/jit status [request_id]`.
func (p *Plugin) handleStatus(args *model.CommandArgs, parts []string) (*model.CommandResponse, *model.AppError) {
	client := p.getAPIClient()
	if client == nil {
		return p.ephemeral(args, "Plugin is not fully configured. Please ask an admin to set the Backend API URL and signing keys."), nil
	}

	requestID := ""
	if len(parts) >= 3 {
		requestID = parts[2]
	}

	handler := commands.NewStatusHandler(p.API, client)
	return handler.HandleStatus(args, requestID)
}

// handleInfo handles `/jit info`.
func (p *Plugin) handleInfo(args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	client := p.getAPIClient()
	if client == nil {
		return p.ephemeral(args, "Plugin is not fully configured. Please ask an admin to set the Backend API URL and signing keys."), nil
	}

	handler := commands.NewInfoHandler(p.API, client)
	return handler.HandleInfo(args)
}

// handleHelp shows the available /jit subcommands.
func (p *Plugin) handleHelp(args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	helpText := `### JIT Access Commands

| Command | Description |
|---------|-------------|
| ` + "`/jit request`" + ` | Open a dialog to create a new JIT access request |
| ` + "`/jit bind <account_id>`" + ` | Bind an AWS account to this channel *(admin only)* |
| ` + "`/jit approvers @user1 @user2 ...`" + ` | Set approvers for bound accounts *(admin only)* |
| ` + "`/jit revoke <request_id>`" + ` | Revoke your own active request, or any request *(admin)* |
| ` + "`/jit status [request_id]`" + ` | Check the status of a request |
| ` + "`/jit info`" + ` | Show bound accounts and approvers for this channel |
| ` + "`/jit help`" + ` | Show this help message |
`
	return p.ephemeral(args, helpText), nil
}

// ephemeral sends an ephemeral post (only visible to the user who invoked the command).
func (p *Plugin) ephemeral(args *model.CommandArgs, message string) *model.CommandResponse {
	post := &model.Post{
		UserId:    args.UserId,
		ChannelId: args.ChannelId,
		Message:   message,
	}
	p.API.SendEphemeralPost(args.UserId, post)

	return &model.CommandResponse{}
}

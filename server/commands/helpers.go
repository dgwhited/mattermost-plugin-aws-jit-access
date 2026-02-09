package commands

import (
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

const (
	// defaultTimeout is the default context timeout for backend API calls.
	defaultTimeout = 15 * time.Second
)

// ephemeralResponse sends an ephemeral post to the command invoker and returns
// an empty command response.
func ephemeralResponse(api plugin.API, args *model.CommandArgs, message string) *model.CommandResponse {
	post := &model.Post{
		UserId:    args.UserId,
		ChannelId: args.ChannelId,
		Message:   message,
	}
	api.SendEphemeralPost(args.UserId, post)
	return &model.CommandResponse{}
}

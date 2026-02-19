package main

import (
	"github.com/mattermost/mattermost/server/public/plugin"

	jitplugin "github.com/dgwhited/mattermost-plugin-aws-jit-access/server/plugin"
)

func main() {
	plugin.ClientMain(&jitplugin.Plugin{})
}

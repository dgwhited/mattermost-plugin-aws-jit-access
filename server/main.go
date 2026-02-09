package main

import (
	jitplugin "github.com/dgwhited/mattermost-plugin-aws-jit-access/server/plugin"
	"github.com/mattermost/mattermost/server/public/plugin"
)

func main() {
	plugin.ClientMain(&jitplugin.Plugin{})
}

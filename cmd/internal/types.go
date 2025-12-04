package internal

import "github.com/coreruleset/go-ftw/config"

type CommandContext struct {
	Configuration         *config.FTWConfiguration
	ConfigurationFileName string
	OverridesFileName     string
	Debug                 bool
	Trace                 bool
	CloudMode             bool
}

func NewCommandContext() *CommandContext {
	return &CommandContext{
		Configuration: config.NewDefaultConfig(),
	}
}

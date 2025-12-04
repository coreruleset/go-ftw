package internal

import "strconv"

// The types in this file satisfy the interface of pflag.Value.
// Using the pflag.Value interface makes it possible to validate
// flag values at parse time, as opposed to using `persistentPreRunE`,
// which would also work, except that persistent run functions will run
// in the child command first, which means that a global flag, like
// `--log-level`, would only be processed `after` other flags, and
// logging as part of flag value validation would then be useless.

type ConfigurationFileNameFlag struct {
	Context *CommandContext
}

type OverridesFileNameFlag struct {
	Context *CommandContext
}

type DebugFlag struct {
	Context *CommandContext
}

type TraceFlag struct {
	Context *CommandContext
}

type CloudFlag struct {
	Context *CommandContext
}

func (c *ConfigurationFileNameFlag) String() string {
	return c.Context.ConfigurationFileName
}

func (c *ConfigurationFileNameFlag) Set(value string) error {
	c.Context.ConfigurationFileName = value
	return nil
}

func (c *ConfigurationFileNameFlag) Type() string {
	return "string"
}

func (c *OverridesFileNameFlag) String() string {
	return c.Context.OverridesFileName
}

func (c *OverridesFileNameFlag) Set(value string) error {
	c.Context.OverridesFileName = value
	return nil
}

func (c *OverridesFileNameFlag) Type() string {
	return "string"
}

func (c *DebugFlag) String() string {
	return strconv.FormatBool(c.Context.Debug)
}

func (c *DebugFlag) Set(value string) error {
	var err error
	c.Context.Debug, err = strconv.ParseBool(value)
	return err
}

func (c *DebugFlag) Type() string {
	return "bool"
}

func (c *TraceFlag) String() string {
	return strconv.FormatBool(c.Context.Trace)
}

func (c *TraceFlag) Set(value string) error {
	var err error
	c.Context.Trace, err = strconv.ParseBool(value)
	return err
}

func (c *TraceFlag) Type() string {
	return "bool"
}

func (c *CloudFlag) String() string {
	return strconv.FormatBool(c.Context.CloudMode)
}

func (c *CloudFlag) Set(value string) error {
	var err error
	c.Context.CloudMode, err = strconv.ParseBool(value)
	return err
}

func (c *CloudFlag) Type() string {
	return "bool"
}

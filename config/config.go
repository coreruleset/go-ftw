package config

// FTWConfig is being exported to be used across the app
var FTWConfig *FTWConfiguration

// FTWConfiguration FTW global Configuration
type FTWConfiguration struct {
	LogFile string     `yaml:"logfile"`
	LogType FTWLogType `yaml:"logtype"`
}

// FTWLogType log readers must implement this one
type FTWLogType struct {
	Name       string `yaml:"name"`
	TimeRegex  string `yaml:"timeregex"`
	TimeFormat string `yaml:"timeformat"`
}

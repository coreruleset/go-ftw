package ftwtest

// UnmarshalYAML is used to unmarshal into map[string]string
// func (h *FTWHeaders) UnmarshalYAML(unmarshal func(interface{}) error) error {
// 	log.Printf("%s", unmarshal(&h.Names))
// 	return unmarshal(&h.Names)
// }

// Input represents the input request in a stage
type Input struct {
	DestAddr       string            `yaml:"dest_addr"`
	Port           int               `yaml:"port"`
	Protocol       string            `yaml:"protocol"`
	URI            string            `yaml:"uri"`
	Version        string            `yaml:"version"`
	Headers        map[string]string `yaml:"headers,omitempty"`
	Method         string            `yaml:"method"`
	Data           string            `yaml:"data,omitempty"`
	SaveCookie     bool              `yaml:"save_cookie,omitempty"`
	StopMagic      bool              `yaml:"stop_magic"`
	EncodedRequest string            `yaml:"encoded_request,omitempty"`
	RAWRequest     string            `yaml:"raw_request,omitempty"`
}

// Output is the response expected from the test
type Output struct {
	Status           []int  `yaml:"status,flow,omitempty"`
	ResponseContains string `yaml:"response_contains,omitempty"`
	LogContains      string `yaml:"log_contains,omitempty"`
	NoLogContains    string `yaml:"no_log_contains,omitempty"`
	ExpectError      bool   `yaml:"expect_error,omitempty"`
}

// FTWTest is the base type used when unmarshaling
type FTWTest struct {
	Meta struct {
		Author      string `yaml:"author,omitempty"`
		Enabled     bool   `yaml:"enabled,omitempty"`
		Name        string `yaml:"name,omitempty"`
		Description string `yaml:"description,omitempty"`
	} `yaml:"meta"`
	Tests []struct {
		TestTitle       string `yaml:"test_title"`
		TestDescription string `yaml:"desc,omitempty"`
		Stages          []struct {
			Stage struct {
				Input  Input  `yaml:"input"`
				Output Output `yaml:"output"`
			} `yaml:"stage"`
		} `yaml:"stages"`
	} `yaml:"tests"`
}

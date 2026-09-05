// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

// Package output provides an interface for showing test results in different formats.
package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/kyokomi/emoji/v2"
	"github.com/rs/zerolog/log"
)

// Type is a string representing the types of output this application has. Each output
// type will be used for printing in a different way, compatible with the type they represent.
type Type string

const (
	Normal   Type = "normal"
	Quiet    Type = "quiet"
	GitHub   Type = "github"
	JSON     Type = "json"
	Plain    Type = "plain"    // when people (or terminals) don't want/support emojis
	Markdown Type = "markdown" // markdown-friendly plain text
)

// AnnotationSeverity is the severity of a GitHub Actions workflow command.
type AnnotationSeverity string

const (
	AnnotationNotice  AnnotationSeverity = "notice"
	AnnotationWarning AnnotationSeverity = "warning"
	AnnotationError   AnnotationSeverity = "error"
)

type catalog map[string]string

// this catalog is used to translate text from basic terminals to enhanced ones that support emoji, just
// because we are fancy. If we are not using a normal output, then just use the key from this map.
var normalCatalog = catalog{
	"** Starting tests!":                    ":hammer_and_wrench:Starting tests!",
	"** Running go-ftw!":                    ":rocket:Running go-ftw!",
	"=> executing tests in file %s":         ":point_right:executing tests in file %s",
	"+ passed in %s (RTT %s)":               ":check_mark:passed in %s (RTT %s)",
	"- %s failed in %s (RTT %s)":            ":collision:%s failed in %s (RTT %s)",
	"= test ignored":                        ":information:test ignored",
	"= test forced to fail":                 ":information:test forced to fail",
	"= test forced to pass":                 ":information:test forced to pass",
	"¯\\_(ツ)_/¯ No tests were run":          ":person_shrugging:No tests were run",
	"+ run %d total tests in %s":            ":plus:run %d total tests in %s",
	">> skipped %d tests":                   ":next_track_button:skipped %d tests",
	"^ ignored %d tests":                    ":index_pointing_up:ignored %d tests",
	"^ forced to pass %d tests":             ":index_pointing_up:forced to pass %d tests",
	"\\o/ All tests successful!":            ":tada:All tests successful!",
	"- %d test(s) failed to run: %+q":       ":thumbs_down:%d test(s) failed to run: %+q",
	"- %d test(s) were forced to fail: %+q": ":index_pointing_up:%d test(s) were forced to fail: %+q",
}

type Output struct {
	OutputType Type
	cat        catalog
	w          io.Writer
	// severity is the severity used for GitHub annotation commands.
	severity AnnotationSeverity
}

// ValidTypes returns an array of the valid output types.
func ValidTypes() []Type {
	return []Type{Normal, Quiet, GitHub, JSON, Plain, Markdown}
}

func (o *Output) Println(format string, a ...interface{}) error {
	err := o.Printf(format+"\n", a...)
	return err
}

func (o *Output) Printf(format string, a ...interface{}) error {
	var s string
	switch o.OutputType {
	case Normal:
		s = emoji.Sprintf(format, a...)
	case Quiet, JSON:
		// don't print anything
		return nil
	case Plain, Markdown:
		s = fmt.Sprintf(format, a...)
	case GitHub:
		s = fmt.Sprintf(format, a...)
		// Println appends the line break to the format string; that break
		// must stay a real newline so each workflow command sits on its own
		// line. Only the message body gets escaped.
		if strings.HasSuffix(s, "\n") {
			s = githubCommand(string(o.severity), strings.TrimSuffix(s, "\n")) + "\n"
		} else {
			s = githubCommand(string(o.severity), s)
		}
	default:
		s = emoji.Sprintf(format, a...)
	}
	_, _ = fmt.Fprintf(o.w, "%s", s)
	return nil
}

// githubCommand formats a GitHub Actions workflow command (annotation).
func githubCommand(severity, message string) string {
	return "::" + severity + "::" + escapeWorkflow(message)
}

// escapeWorkflow URL-encodes the characters that are not allowed inside a
// GitHub workflow command. Order matters: '%' must be escaped first.
func escapeWorkflow(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

func (o *Output) RawPrint(s string) {
	_, _ = fmt.Fprintf(o.w, "%s", s)
}

// NewOutput returns a new output with the proper output format for the selected output type
func NewOutput(o string, w io.Writer) *Output {
	log.Trace().Msgf("ftw/output: creating output %s\n", o)
	out := &Output{
		OutputType: Normal,
		cat:        normalCatalog,
		w:          w,
		severity:   AnnotationNotice,
	}
	switch strings.ToLower(o) {
	case "quiet":
		out.OutputType = Quiet
	case "github":
		out.cat = createPlainCatalog(normalCatalog)
		out.OutputType = GitHub
	case "json":
		out.OutputType = JSON
	case "plain":
		out.cat = createPlainCatalog(normalCatalog)
		out.OutputType = Plain
	case "markdown":
		out.cat = createPlainCatalog(normalCatalog)
		out.OutputType = Markdown
	case "normal":
		break
	default:
		log.Info().Msgf("ftw/output: unknown type \"%s\". Using normal output.\n", o)
	}
	return out
}

// Message predefined messages that might have different types depending on the output type.
// All message in catalogs, where the text in the message is used as a key to get the corresponding text.
func (o *Output) Message(key string) string {
	text, found := o.cat[key]
	if !found {
		text = ""
	}
	return text
}

func (o *Output) IsJson() bool {
	return o.OutputType == JSON
}

func (o *Output) IsMarkdown() bool {
	return o.OutputType == Markdown
}

// SetSeverity overrides the severity used for GitHub annotation commands.
func (o *Output) SetSeverity(severity AnnotationSeverity) {
	o.severity = severity
}

func createPlainCatalog(c catalog) catalog {
	plainCatalog := catalog{}
	for k := range c {
		plainCatalog[k] = k
	}
	return plainCatalog
}

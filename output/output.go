// Package output provides an interface for outputting test results in different formats.
package output

import (
	"fmt"
	"io"

	"encoding/json"

	"github.com/kyokomi/emoji"
	"github.com/rs/zerolog/log"
)

type OutputType int

const (
	Normal OutputType = iota
	Quiet
	GitHub
	GitLab
	CircleCI
	CodeBuild
	Jenkins
	JSON
)

func (o OutputType) String() string {
	switch o {
	case Normal:
		return "normal"
	case Quiet:
		return "quiet"
	case GitHub:
		return "github"
	case GitLab:
		return "gitlab"
	case JSON:
		return "json"
	case Jenkins:
		return "jenkins"
	case CircleCI:
		return "circleci"
	case CodeBuild:
		return "codebuild"
	}
	return "unknown"
}

type Output struct {
	oType OutputType
	w     io.Writer
}

type iOutput interface {
	Notice(format string, a ...interface{}) error
	Warn(format string, a ...interface{}) error
	Err(format string, a ...interface{}) error
}

func (o *Output) Notice(format string, a ...interface{}) error {
	var s string
	switch o.oType {
	case Normal:
		s = emoji.Sprintf(format, a...)
	case Quiet:
		// don't print anything
		s = ""
	case GitHub:
		s = fmt.Sprintf(format, a...)
		s = fmt.Sprintf("::notice file={name},line={line},endLine={endLine},title={title}::{%s}", s)
	case JSON:
		s = fmt.Sprintf(format, a...)
		s = "{\"level\": \"notice\", \"message\":\"" + s + "\"}"
		b, err := json.Marshal(s)
		if err != nil {
			s = string(b)
		} else {
			s = ""
		}
	default:
		s = emoji.Sprintf(format, a...)
	}
	fmt.Fprintf(o.w, "%s\n", s)
	return nil
}

// Warn will return an empty string
func (o *Output) Warn(format string, a ...interface{}) error {
	var s string
	switch o.oType {
	case Normal:
		s = emoji.Sprintf(format, a...)
	case Quiet:
		// don't print anything
		s = ""
	case GitHub:
		s = fmt.Sprintf(format, a...)
		s = fmt.Sprintf("::warning file={name},line={line},endLine={endLine},title={title}::{%s}", s)
	case JSON:
		s = fmt.Sprintf(format, a...)
		b, err := json.Marshal(s)
		if err != nil {
			s = string(b)
		} else {
			s = ""
		}
	default:
		s = emoji.Sprintf(format, a...)
	}
	fmt.Fprintf(o.w, "%s\n", s)
	return nil
}

// Err print the error message
func (o *Output) Err(format string, a ...interface{}) error {
	var s string
	var err error

	switch o.oType {
	case Normal:
		s = emoji.Sprintf(format, a...)
	case Quiet:
		// don't print anything
		s = ""
	case GitHub:
		s = fmt.Sprintf(format, a...)
		s = fmt.Sprintf("::error file={name},line={line},endLine={endLine},title={title}::{%s}", s)
	case JSON:
		s = fmt.Sprintf(format, a...)
		b, err := json.Marshal(s)
		if err != nil {
			s = string(b)
		} else {
			s = ""
		}
	default:
		s = emoji.Sprintf(format, a...)
	}
	fmt.Fprintf(o.w, "%s\n", s)
	return err
}

// NewOutput returns a new output with the proper output format for that CI
// or an error if there is nothing implemented
func NewOutput(o OutputType, w io.Writer) iOutput {
	var out iOutput
	log.Trace().Msgf("ftw/output: creating output %s\n", o)
	switch o {
	case Quiet:
		out = &Output{
			oType: Quiet,
			w:     w,
		}
	case GitHub:
		out = &Output{
			oType: GitHub,
			w:     w,
		}
	case JSON:
		out = &Output{
			oType: JSON,
			w:     w,
		}
	case GitLab:
		out = &Output{
			oType: GitLab,
			w:     w,
		}
	case CircleCI:
		out = &Output{
			oType: CircleCI,
			w:     w,
		}
	case CodeBuild:
		out = &Output{
			oType: CodeBuild,
			w:     w,
		}
	case Jenkins:
		out = &Output{
			oType: Jenkins,
			w:     w,
		}
	default:
		out = &Output{
			oType: Normal,
			w:     w,
		}
	}

	return out
}

// Package output provides an interface for showing test results in different formats.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kyokomi/emoji"
	"github.com/rs/zerolog/log"
)

// Type is a string representing the types of output this application has. Each output
// type will be used for printing in a different way, compatible with the type they represent.
type Type string

const (
	Normal Type = "normal"
	Quiet  Type = "quiet"
	GitHub Type = "github"
	JSON   Type = "json"
)

type Output struct {
	oType            Type
	w                io.Writer
	showOnlyFailures bool
}

func (o *Output) Type() Type {
	return o.oType
}

func (o *Output) Println(format string, a ...interface{}) error {
	err := o.Printf(format+"\n", a...)
	return err
}

func (o *Output) Printf(format string, a ...interface{}) error {
	var s string
	switch o.oType {
	case Normal:
		s = emoji.Sprintf(format, a...)
	case Quiet:
		// don't print anything
		return nil
	case GitHub:
		s = fmt.Sprintf(format, a...)
		s = fmt.Sprintf("::notice file={name},line={line},endLine={endLine},title={title}::{%s}", s)
	case JSON:
		s = fmt.Sprintf(format, a...)
		s = "{\"level\": \"notice\", \"message\":\"" + s + "\"}"
		b, err := json.Marshal(s)
		s = string(b)
		if err != nil {
			return err
		}
	default:
		s = emoji.Sprintf(format, a...)
	}
	_, _ = fmt.Fprintf(o.w, "%s", s)
	return nil
}

func (o *Output) RawPrint(s string) {
	_, _ = fmt.Fprintf(o.w, "%s", s)
}

// NewOutput returns a new output with the proper output format for that CI
func NewOutput(o string, w io.Writer) *Output {
	var out *Output
	log.Trace().Msgf("ftw/output: creating output %s\n", o)
	switch strings.ToLower(o) {
	case "quiet":
		out = &Output{
			oType: Quiet,
			w:     w,
		}
	case "github":
		out = &Output{
			oType: GitHub,
			w:     w,
		}
	case "json":
		out = &Output{
			oType: JSON,
			w:     w,
		}
	case "normal":
		out = &Output{
			oType: Normal,
			w:     w,
		}
	default:
		log.Info().Msgf("ftw/output: unknown type \"%s\". Using normal output.\n", o)
		out = &Output{
			oType: Normal,
			w:     w,
		}
	}
	return out
}

// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package leipzig

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/suite"
)

type payloadTestSuite struct {
	suite.Suite
}

func TestPayloadTestSuite(t *testing.T) {
	suite.Run(t, new(payloadTestSuite))
}

func (s *payloadTestSuite) TestNewPayload() {
	type args struct {
		line string
	}
	tests := []struct {
		name string
		args args
		want *Payload
	}{
		{
			name: "TestNewPayload",
			args: args{
				line: "1\t$156,834 for The Pathway to Excellence in Practice program through Neighborhood Place of Puna.",
			},
			want: &Payload{
				line:    1,
				payload: "$156,834 for The Pathway to Excellence in Practice program through Neighborhood Place of Puna.",
			},
		},
		{
			name: "TestAdditional",
			args: args{
				line: "2000\tThis is an additional payload",
			},
			want: &Payload{
				line:    2000,
				payload: "This is an additional payload",
			},
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			if got := NewPayload(tt.args.line); !reflect.DeepEqual(got, tt.want) {
				s.Require().Equal(got, tt.want)
			}
		})
	}
}

func (s *payloadTestSuite) TestPayload_Content() {
	type fields struct {
		line    int
		payload string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "TestContent",
			fields: fields{
				line:    1,
				payload: "$156,834 for The Pathway to Excellence in Practice program through Neighborhood Place of Puna.",
			},
			want: "$156,834 for The Pathway to Excellence in Practice program through Neighborhood Place of Puna.",
		},
		{
			name: "TestContent2",
			fields: fields{
				line:    2000,
				payload: "This is another test payload",
			},
			want: "This is another test payload",
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			p := &Payload{
				line:    tt.fields.line,
				payload: tt.fields.payload,
			}
			if got := p.Content(); got != tt.want {
				s.Require().Equal(got, tt.want)
			}
		})
	}
}

func (s *payloadTestSuite) TestPayload_LineNumber() {
	type fields struct {
		line    int
		payload string
	}
	tests := []struct {
		name   string
		fields fields
		want   int
	}{
		{
			name: "TestLineNumber",
			fields: fields{
				line:    1,
				payload: "This is a test payload",
			},
			want: 1,
		},
		{
			name: "TestLineNumber2",
			fields: fields{
				line:    2000,
				payload: "This is another test payload",
			},
			want: 2000,
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			p := &Payload{
				line:    tt.fields.line,
				payload: tt.fields.payload,
			}
			if got := p.LineNumber(); got != tt.want {
				s.Require().Equal(got, tt.want)
			}
		})
	}
}

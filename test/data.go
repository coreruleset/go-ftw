// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"bytes"
	"encoding/base64"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/rs/zerolog/log"
)

// GetData returns the body data for the request, whether specified via `data` or `encoded_data`.
// If `data` contains Go templates, these will be evaluated.
func (i *Input) GetData() []byte {
	if i.Data != nil {
		return i.parseData()
	}
	if i.EncodedData != nil {
		decoded, err := base64.StdEncoding.DecodeString(*i.EncodedData)
		if err != nil {
			log.Debug().Msgf("test/data: error decoding data fro Base64: %s", err.Error())
			return nil
		}
		return decoded
	}

	return nil
}

func (i *Input) parseData() []byte {
	if i.Data == nil {
		return nil
	}

	var err error
	var tpl bytes.Buffer

	// Parse data for Go template
	t := template.New("ftw").Funcs(sprig.TxtFuncMap())
	t, err = t.Parse(*i.Data)
	if err != nil {
		log.Debug().Msgf("test/data: error parsing template in data: %s", err.Error())
		return nil
	}
	if err = t.Execute(&tpl, nil); err != nil {
		log.Debug().Msgf("test/data: error executing template: %s", err.Error())
		return nil
	}

	return tpl.Bytes()
}

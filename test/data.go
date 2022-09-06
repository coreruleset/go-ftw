package test

import (
	"bytes"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/rs/zerolog/log"
)

// ParseData returns the data from the test. Will parse and interpret Go text/template inside it.
func (i *Input) ParseData() []byte {
	var err error
	var tpl bytes.Buffer

	// Parse data for Go template
	if i.Data != nil {
		t := template.New("ftw").Funcs(sprig.TxtFuncMap())
		t, err = t.Parse(*i.Data)
		if err != nil {
			log.Debug().Msgf("test/data: error parsing template in data: %s", err.Error())
		}
		if err = t.Execute(&tpl, nil); err != nil {
			log.Debug().Msgf("test/data: error executing template: %s", err.Error())
		}
	}

	return tpl.Bytes()
}

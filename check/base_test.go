package check

import (
	"testing"
	"time"

	"github.com/fzipi/go-ftw/config"
)

var yamlApacheConfig = `
---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
logtype:
  name: 'apache'
  timeregex:  '\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]'
  timeformat: 'ddd MMM DD HH:mm:ss.S YYYY'
`

var yamlNginxConfig = `
---
logfile: 'tests/logs/modsec3-nginx/nginx/error.log'
logtype:
  name: 'nginx'
  timeregex:  '(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})'
  timeformat: 'YYYY/MM/DD HH:mm:ss'
  timetruncate: 1s
`

func TestNewCheck(t *testing.T) {
	config.ImportFromString(yamlNginxConfig)

	c := NewCheck(config.FTWConfig)

	if c.log.TimeTruncate != time.Second {
		t.Errorf("Failed")
	}
}

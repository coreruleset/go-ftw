// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"bytes"
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/rs/zerolog/log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/template"
)

const (
	defaultPrefix     = "."
	testingConfigTmpl = `SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
     "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "^application/[a-z0-9.-]+[+]json" \
     "id:'200006',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRequestBodyLimit 13107200
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction Reject
SecRule REQBODY_ERROR "!@eq 0" \
    "id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
    "id:'200003',phase:2,t:none,log,deny,status:400, \
    msg:'Multipart request body failed strict validation."
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml
SecResponseBodyLimit 524288
SecResponseBodyLimitAction ProcessPartial
SecDataDir /tmp/
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:(5|4)(0|1)[0-9])$"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAction \
    "id:900000,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.7.0-dev',\
    setvar:tx.blocking_paranoia_level={{ .ParanoiaLevel }}"
`
)

type LocalEngine struct {
	waf coraza.WAF
}

// NewEngine creates a new engine to test payloads
func NewEngine(prefix string, paranoia int) *LocalEngine {
	eng := &LocalEngine{
		waf: crsWAF(prefix, paranoia),
	}
	return eng
}

// CRSCall benchmarks the CRS WAF with a GET request
// payload: the string to be passed in the request body
// returns the status of the transaction and a map of the matched rules with their IDs and the data that matched.
func (e *LocalEngine) CRSCall(payload string) (int, map[int]string) {
	var status = http.StatusOK
	var matchedRules = make(map[int]string)

	tx := e.waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 8080)
	tx.ProcessURI("/post", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "localhost")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75. 0.3770.100 Safari/537.36")
	tx.AddRequestHeader("Accept", "application/json")
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	body := []byte("payload=" + url.QueryEscape(payload))

	tx.AddRequestHeader("Content-Length", strconv.Itoa(len(body)))
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody(body); err != nil {
		log.Error().Err(err).Msg("failed to write request body")
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		log.Error().Err(err).Msg("failed to process request body")
	}
	if it != nil { // execution was interrupted
		status = obtainStatusCodeFromInterruptionOrDefault(it, http.StatusOK)
		matchedRules = getMatchedRules(tx)
	}
	// We don't care about the response body for now, nor logging.
	if err := tx.Close(); err != nil {
		log.Error().Err(err).Msg("failed to close transaction")
	}

	return status, matchedRules
}

// crsWAF creates a WAF with the CRS rules
// prefix: the path to the CRS rules
// paranoiaLevel: 1 - 4 should be added as a template to the crs-setup.conf file
// If you want to run your own waf rules instead of crs, create a similar function to crsWAF
func crsWAF(prefix string, paranoiaLevel int) coraza.WAF {
	if prefix == "" {
		prefix = defaultPrefix
	}
	// test if the prefix is a valid path
	if _, err := os.Stat(fmt.Sprintf("%s/crs-setup.conf.example", prefix)); err != nil {
		if _, err = os.Stat(fmt.Sprintf("%s/rules", prefix)); err != nil {
			log.Fatal().Err(err).Msg("failed to find the CRS rules")
		}
	}
	// inject variables into config template
	vars := map[string]interface{}{
		"ParanoiaLevel": paranoiaLevel,
	}
	log.Debug().Msgf("Using paranoia level: %d\n", paranoiaLevel)
	// set up configuration from template
	configTmpl, err := template.New("crs-config").Parse(testingConfigTmpl)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse config template")
	}
	crsConfig := &bytes.Buffer{}
	err = configTmpl.Execute(crsConfig, vars)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to inject variables into config template")
	}

	conf := coraza.NewWAFConfig().
		WithDirectives(crsConfig.String()).
		WithDirectives(fmt.Sprintf("Include %s/crs-setup.conf.example", prefix)).
		WithDirectives(fmt.Sprintf("Include %s/rules/R*.conf", prefix))

	waf, err := coraza.NewWAF(conf)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create WAF")
	}
	return waf
}

func obtainStatusCodeFromInterruptionOrDefault(it *types.Interruption, defaultStatusCode int) int {
	if it.Action == "deny" {
		statusCode := it.Status
		if statusCode == 0 {
			statusCode = 403
		}

		return statusCode
	}

	return defaultStatusCode
}

// getMatchedRules returns the IDs of the rules that matched
func getMatchedRules(tx types.Transaction) map[int]string {
	var matchedRules = make(map[int]string)

	for _, rule := range tx.MatchedRules() {
		id := rule.Rule().ID()
		if needToDiscardAdminRule(id) {
			continue
		}
		matchedRules[id] = rule.Data()
	}

	return matchedRules
}

// needToDiscardAdminRule checks if the rule is an admin rule
// Administrative rules are used to separate logically between
// different paranoia levels, for example.
func needToDiscardAdminRule(id int) bool {
	strId := strconv.Itoa(id)
	if id < 902000 || /* configuration rules */
		id > 949000 || /* reporting ruls */
		id == 941010 || /* special rule to remove REQUEST_FILENAME from the target list of all the 941xxx rules */
		strings.HasSuffix(strId, "11") || /* detection paranoia level < 1, phase:1 rule */
		strings.HasSuffix(strId, "12") || /* detection paranoia level < 1, phase:2 rule */
		strings.HasSuffix(strId, "13") || /* detection paranoia level < 2, phase:1 rule */
		strings.HasSuffix(strId, "14") || /* detection paranoia level < 2, phase:2 rule */
		strings.HasSuffix(strId, "15") || /* detection paranoia level < 3, phase:1 rule */
		strings.HasSuffix(strId, "16") || /* detection paranoia level < 3, phase:2 rule */
		strings.HasSuffix(strId, "17") || /* detection paranoia level < 4, phase:1 rule */
		strings.HasSuffix(strId, "18") { /* detection paranoia level < 4, phase:2 rule */
		return true
	}
	return false
}

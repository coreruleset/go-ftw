package check

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreruleset/go-ftw/config"
)

var statusOKTests = []struct {
	status         int
	expectedStatus []int
}{
	{400, []int{0, 100, 200, 400}},
	{400, []int{400}},
}

var statusFailTests = []struct {
	status         int
	expectedStatus []int
}{
	{400, []int{0, 100, 200}},
	{200, []int{400}},
	{200, []int{0}},
}

func TestStatusOK(t *testing.T) {
	err := config.NewConfigFromString(yamlApacheConfig)
	assert.NoError(t, err)

	c := NewCheck(config.FTWConfig)

	for _, expected := range statusOKTests {
		c.SetExpectStatus(expected.expectedStatus)
		assert.True(t, c.AssertStatus(expected.status))
	}
}

func TestStatusFail(t *testing.T) {
	err := config.NewConfigFromString(yamlApacheConfig)
	assert.NoError(t, err)

	c := NewCheck(config.FTWConfig)

	for _, expected := range statusFailTests {
		c.SetExpectStatus(expected.expectedStatus)
		assert.False(t, c.AssertStatus(expected.status))
	}
}

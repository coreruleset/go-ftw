package check

import (
	"testing"

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
	if err != nil {
		t.Errorf("Failed!")
	}

	c := NewCheck(config.FTWConfig)

	for _, expected := range statusOKTests {
		c.SetExpectStatus(expected.expectedStatus)
		if !c.AssertStatus(expected.status) {
			t.Errorf("Failed !")
		}
	}
}

func TestStatusFail(t *testing.T) {
	err := config.NewConfigFromString(yamlApacheConfig)
	if err != nil {
		t.Errorf("Failed!")
	}

	c := NewCheck(config.FTWConfig)

	for _, expected := range statusFailTests {
		c.SetExpectStatus(expected.expectedStatus)
		if c.AssertStatus(expected.status) {
			t.Errorf("Failed !")
		}
	}
}

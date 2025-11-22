package utils

import (
	"fmt"

	"github.com/google/uuid"
)

const (
	// Start and end suffixes are used to disambiguate start and end markers.
	// The suffixes make the markers unique, while still maintaining one UUID per stage.
	stageIdStartSuffix = "-s"
	stageIdEndSuffix   = "-e"
)

func GenerateStageId(ruleId uint, testId uint) string {
	return fmt.Sprintf("%d-%d-%s", ruleId, testId, uuid.NewString())
}

func CreateStartMarker(stageId string) string {
	return stageId + stageIdStartSuffix
}

func CreateEndMarker(stageId string) string {
	return stageId + stageIdEndSuffix
}

package formatter

import (
	"encoding/json"

	"github.com/secopsium/secopsium-cli/internal/model"
)

func JSON(result model.ScanResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

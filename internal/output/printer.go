package output

import (
	"errors"
	"fmt"

	"github.com/secopsium/secopsium-cli/internal/config"
	"github.com/secopsium/secopsium-cli/internal/formatter"
	"github.com/secopsium/secopsium-cli/internal/model"
	"github.com/secopsium/secopsium-cli/internal/redact"
)

func Print(result model.ScanResult, format string, noColor bool, unsafeRawOutput bool) error {
	safeResult := redact.ScanResult(result, unsafeRawOutput)

	switch format {
	case config.FormatJSON:
		rendered, err := formatter.JSON(safeResult)
		if err != nil {
			return err
		}
		fmt.Println(rendered)
		return nil
	case config.FormatHuman:
		rendered := formatter.NewHumanFormatter(noColor).Format(safeResult)
		fmt.Println(rendered)
		return nil
	default:
		return errors.New("unsupported output format: " + format)
	}
}

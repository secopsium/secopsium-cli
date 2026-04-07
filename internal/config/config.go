package config

import (
	"errors"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	FormatHuman = "human"
	FormatJSON  = "json"
)

type Settings struct {
	OutputFormat string `yaml:"output_format"`
}

func DefaultSettings() Settings {
	return Settings{
		OutputFormat: FormatHuman,
	}
}

func Load(path string) (Settings, error) {
	settings := DefaultSettings()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return settings, nil
		}
		return settings, err
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return settings, nil
	}

	if err := yaml.Unmarshal(data, &settings); err != nil {
		return settings, err
	}

	return normalize(settings), nil
}

func Save(path string, settings Settings) error {
	normalized := normalize(settings)
	data, err := yaml.Marshal(normalized)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func normalize(settings Settings) Settings {
	format := strings.ToLower(strings.TrimSpace(settings.OutputFormat))
	switch format {
	case FormatJSON:
		settings.OutputFormat = FormatJSON
	default:
		settings.OutputFormat = FormatHuman
	}
	return settings
}

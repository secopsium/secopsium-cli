package repo

import "testing"

func TestValidateURLAllowsHTTPSAndSSH(t *testing.T) {
	valid := []string{
		"https://github.com/secopsium/secopsium-cli.git",
		"ssh://git@github.com/secopsium/secopsium-cli.git",
	}

	for _, value := range valid {
		if _, err := ValidateURL(value, false); err != nil {
			t.Fatalf("expected URL %q to validate: %v", value, err)
		}
	}
}

func TestValidateURLRejectsDisallowedSchemes(t *testing.T) {
	invalid := []string{
		"file:///tmp/repo.git",
		"git@github.com:secopsium/secopsium-cli.git",
		"ftp://example.com/repo.git",
	}

	for _, value := range invalid {
		if _, err := ValidateURL(value, false); err == nil {
			t.Fatalf("expected URL %q to be rejected", value)
		}
	}
}

func TestValidateURLAllowsFileWhenExplicitlyEnabled(t *testing.T) {
	if _, err := ValidateURL("file:///tmp/repo.git", true); err != nil {
		t.Fatalf("expected file URL to validate when enabled: %v", err)
	}
}

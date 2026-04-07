package repo

import (
	"fmt"
	"net/url"
	"strings"
)

func ValidateURL(rawURL string, allowFileURL bool) (*url.URL, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil, fmt.Errorf("repository URL is required")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid repository URL: %w", err)
	}
	if strings.TrimSpace(parsed.Scheme) == "" {
		return nil, fmt.Errorf("repository URL must include an explicit scheme")
	}

	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))

	switch scheme {
	case "https", "ssh":
		if strings.TrimSpace(parsed.Host) == "" {
			return nil, fmt.Errorf("repository URL must include a host")
		}
	case "file":
		if !allowFileURL {
			return nil, fmt.Errorf("file:// repository URLs are disabled by default; pass --allow-file-url to enable them")
		}
		if strings.TrimSpace(parsed.Path) == "" {
			return nil, fmt.Errorf("file:// repository URL must include a path")
		}
	default:
		return nil, fmt.Errorf("unsupported repository URL scheme %q; allowed schemes are https:// and ssh://", parsed.Scheme)
	}

	return parsed, nil
}

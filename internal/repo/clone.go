package repo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

const DefaultMaxRepoSizeBytes int64 = 512 * 1024 * 1024

var errRepoTooLarge = errors.New("repo_too_large")

type CloneRequest struct {
	URL          string
	Ref          string
	MaxSizeBytes int64
}

func CloneToTemp(ctx context.Context, req CloneRequest) (string, error) {
	tempDir, err := os.MkdirTemp("", "secopsium-cli-*")
	if err != nil {
		return "", fmt.Errorf("create temp directory: %w", err)
	}

	options := &git.CloneOptions{
		URL:               req.URL,
		Depth:             1,
		SingleBranch:      true,
		RecurseSubmodules: git.NoRecurseSubmodules,
		Tags:              git.NoTags,
	}
	if strings.TrimSpace(req.Ref) != "" {
		options.ReferenceName = plumbing.NewBranchReferenceName(strings.TrimSpace(req.Ref))
	}

	_, err = git.PlainCloneContext(ctx, tempDir, false, options)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		if ctx.Err() != nil {
			return "", fmt.Errorf("clone repository %q: %w", req.URL, ctx.Err())
		}
		return "", fmt.Errorf("clone repository %q: %w", req.URL, err)
	}

	maxSizeBytes := req.MaxSizeBytes
	if maxSizeBytes <= 0 {
		maxSizeBytes = DefaultMaxRepoSizeBytes
	}
	totalBytes, err := checkRepoSize(tempDir, maxSizeBytes)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return "", err
	}
	_ = totalBytes

	return tempDir, nil
}

func checkRepoSize(root string, maxBytes int64) (int64, error) {
	var totalBytes int64

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		totalBytes += info.Size()
		if totalBytes > maxBytes {
			return errRepoTooLarge
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errRepoTooLarge) {
			return totalBytes, fmt.Errorf("repository exceeds max size of %d MB", maxBytes/(1024*1024))
		}
		return totalBytes, err
	}

	return totalBytes, nil
}

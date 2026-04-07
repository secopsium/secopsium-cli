package tools

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

type ToolID string

const (
	ToolGitleaks ToolID = "gitleaks"
	ToolSemgrep  ToolID = "semgrep"
)

type InstallMethod string

const (
	InstallMethodArchive InstallMethod = "archive"
	InstallMethodPython  InstallMethod = "python-venv"
)

type ToolSpec struct {
	ID             ToolID
	DisplayName    string
	Command        string
	Version        string
	InstallMethod  InstallMethod
	VersionArgs    []string
	ArchiveTargets map[string]ArchiveTarget
}

type ArchiveTarget struct {
	URL         string
	SHA256      string
	ArchiveType string
	BinaryName  string
}

type ResolvedTool struct {
	Spec       ToolSpec
	Ready      bool
	Managed    bool
	Path       string
	PathDir    string
	Version    string
	StatusText string
}

type Manager struct {
	rootDir string
}

func NewManager(rootDir string) *Manager {
	if strings.TrimSpace(rootDir) == "" {
		rootDir = DefaultToolsDir()
	}
	return &Manager{rootDir: rootDir}
}

func DefaultToolsDir() string {
	if env := strings.TrimSpace(os.Getenv("SECOPSIUM_TOOLS_DIR")); env != "" {
		return env
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil || strings.TrimSpace(cacheDir) == "" {
		return ".secopsium-tools"
	}
	return filepath.Join(cacheDir, "secopsium", "tools")
}

func SupportedTools() []ToolSpec {
	return []ToolSpec{
		{
			ID:            ToolGitleaks,
			DisplayName:   "Gitleaks",
			Command:       binaryName("gitleaks"),
			Version:       "8.30.0",
			InstallMethod: InstallMethodArchive,
			VersionArgs:   []string{"version"},
			ArchiveTargets: map[string]ArchiveTarget{
				"darwin/amd64": {
					URL:         "https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_darwin_x64.tar.gz",
					SHA256:      "ca221d012d247080c2f6f61f4b7a83bffa2453806b0c195c795bbe9a8c775ed5",
					ArchiveType: "tar.gz",
					BinaryName:  "gitleaks",
				},
				"darwin/arm64": {
					URL:         "https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_darwin_arm64.tar.gz",
					SHA256:      "b251ab2bcd4cd8ba9e56ff37698c033ebf38582b477d21ebd86586d927cf87e7",
					ArchiveType: "tar.gz",
					BinaryName:  "gitleaks",
				},
				"linux/amd64": {
					URL:         "https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_linux_x64.tar.gz",
					SHA256:      "79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e",
					ArchiveType: "tar.gz",
					BinaryName:  "gitleaks",
				},
				"linux/arm64": {
					URL:         "https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_linux_arm64.tar.gz",
					SHA256:      "b4cbbb6ddf7d1b2a603088cd03a4e3f7ce48ee7fd449b51f7de6ee2906f5fa2f",
					ArchiveType: "tar.gz",
					BinaryName:  "gitleaks",
				},
				"windows/amd64": {
					URL:         "https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_windows_x64.zip",
					SHA256:      "54fe94f644b832dd08e8c3a5915efb3bfa862386d59fb27ca0792cb687a83573",
					ArchiveType: "zip",
					BinaryName:  "gitleaks.exe",
				},
			},
		},
		{
			ID:            ToolSemgrep,
			DisplayName:   "Semgrep",
			Command:       binaryName("semgrep"),
			Version:       "1.156.0",
			InstallMethod: InstallMethodPython,
			VersionArgs:   []string{"--version"},
		},
	}
}

func RequiredScanTools() []ToolID {
	return []ToolID{ToolGitleaks, ToolSemgrep}
}

func (m *Manager) RootDir() string {
	return m.rootDir
}

func (m *Manager) Resolve(ctx context.Context, toolIDs []ToolID) ([]ResolvedTool, error) {
	specs := specsFor(toolIDs)
	resolved := make([]ResolvedTool, 0, len(specs))
	for _, spec := range specs {
		item, err := m.resolveOne(ctx, spec)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, item)
	}
	return resolved, nil
}

func (m *Manager) Install(ctx context.Context, toolIDs []ToolID, log io.Writer) ([]ResolvedTool, error) {
	specs := specsFor(toolIDs)
	installed := make([]ResolvedTool, 0, len(specs))
	for _, spec := range specs {
		if log != nil {
			fmt.Fprintf(log, "  - installing %s %s\n", spec.DisplayName, spec.Version)
		}
		if err := m.installOne(ctx, spec, log); err != nil {
			return nil, err
		}
		item, err := m.resolveOne(ctx, spec)
		if err != nil {
			return nil, err
		}
		installed = append(installed, item)
	}
	return installed, nil
}

func (m *Manager) PrependToPATH(tools []ResolvedTool) func() {
	original := os.Getenv("PATH")
	dirs := make([]string, 0, len(tools))
	for _, tool := range tools {
		if !tool.Managed || strings.TrimSpace(tool.PathDir) == "" {
			continue
		}
		if !slices.Contains(dirs, tool.PathDir) {
			dirs = append(dirs, tool.PathDir)
		}
	}
	if len(dirs) == 0 {
		return func() {}
	}

	newPath := strings.Join(append(dirs, original), string(os.PathListSeparator))
	_ = os.Setenv("PATH", newPath)
	return func() {
		_ = os.Setenv("PATH", original)
	}
}

func MissingTools(resolved []ResolvedTool) []ToolID {
	missing := make([]ToolID, 0)
	for _, tool := range resolved {
		if !tool.Ready {
			missing = append(missing, tool.Spec.ID)
		}
	}
	return missing
}

func (m *Manager) resolveOne(ctx context.Context, spec ToolSpec) (ResolvedTool, error) {
	managedPath := m.managedCommandPath(spec)
	if fileExists(managedPath) {
		version := detectVersion(ctx, managedPath, spec.VersionArgs)
		return ResolvedTool{
			Spec:       spec,
			Ready:      true,
			Managed:    true,
			Path:       managedPath,
			PathDir:    filepath.Dir(managedPath),
			Version:    version,
			StatusText: "managed",
		}, nil
	}

	systemPath, err := exec.LookPath(spec.Command)
	if err == nil {
		version := detectVersion(ctx, systemPath, spec.VersionArgs)
		return ResolvedTool{
			Spec:       spec,
			Ready:      true,
			Managed:    false,
			Path:       systemPath,
			PathDir:    filepath.Dir(systemPath),
			Version:    version,
			StatusText: "system",
		}, nil
	}

	return ResolvedTool{
		Spec:       spec,
		Ready:      false,
		StatusText: "missing",
	}, nil
}

func (m *Manager) installOne(ctx context.Context, spec ToolSpec, log io.Writer) error {
	switch spec.InstallMethod {
	case InstallMethodArchive:
		return m.installArchiveTool(ctx, spec, log)
	case InstallMethodPython:
		return m.installSemgrep(ctx, spec, log)
	default:
		return fmt.Errorf("unsupported install method %q for %s", spec.InstallMethod, spec.ID)
	}
}

func (m *Manager) installArchiveTool(ctx context.Context, spec ToolSpec, log io.Writer) error {
	target, ok := spec.ArchiveTargets[platformKey()]
	if !ok {
		return fmt.Errorf("%s does not provide a managed binary for %s/%s", spec.DisplayName, runtime.GOOS, runtime.GOARCH)
	}

	installDir := filepath.Dir(m.managedCommandPath(spec))
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return fmt.Errorf("create install directory for %s: %w", spec.DisplayName, err)
	}

	tempDir, err := os.MkdirTemp("", "secopsium-tool-*")
	if err != nil {
		return fmt.Errorf("create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	archivePath := filepath.Join(tempDir, filepath.Base(target.URL))
	if log != nil {
		fmt.Fprintf(log, "    downloading %s\n", target.URL)
	}
	if err := downloadFile(ctx, target.URL, archivePath, target.SHA256); err != nil {
		return err
	}

	extractedBinary, err := extractBinary(archivePath, target.ArchiveType, target.BinaryName, tempDir)
	if err != nil {
		return err
	}

	finalPath := m.managedCommandPath(spec)
	if err := copyExecutable(extractedBinary, finalPath); err != nil {
		return err
	}
	return nil
}

func (m *Manager) installSemgrep(ctx context.Context, spec ToolSpec, log io.Writer) error {
	python, err := findPython(ctx)
	if err != nil {
		return err
	}

	venvDir := filepath.Join(m.rootDir, string(spec.ID), spec.Version, "venv")
	if err := os.MkdirAll(filepath.Dir(venvDir), 0o755); err != nil {
		return fmt.Errorf("create semgrep install directory: %w", err)
	}

	if !fileExists(m.managedCommandPath(spec)) {
		if log != nil {
			fmt.Fprintf(log, "    creating managed Python environment with %s\n", python.DisplayName)
		}
		if err := runCommand(ctx, log, python.Command, append(python.Args, "-m", "venv", venvDir)...); err != nil {
			return fmt.Errorf("create semgrep virtualenv: %w", err)
		}
	}

	venvPython := managedPythonPath(venvDir)
	if log != nil {
		fmt.Fprintf(log, "    installing semgrep==%s\n", spec.Version)
	}
	if err := runCommand(ctx, log, venvPython, "-m", "pip", "install", "--upgrade", "pip"); err != nil {
		return fmt.Errorf("bootstrap pip for semgrep: %w", err)
	}
	if err := runCommand(ctx, log, venvPython, "-m", "pip", "install", "--upgrade", fmt.Sprintf("semgrep==%s", spec.Version)); err != nil {
		return fmt.Errorf("install semgrep: %w", err)
	}

	if !fileExists(m.managedCommandPath(spec)) {
		return fmt.Errorf("semgrep install completed but command was not found at %s", m.managedCommandPath(spec))
	}
	return nil
}

func (m *Manager) managedCommandPath(spec ToolSpec) string {
	switch spec.InstallMethod {
	case InstallMethodPython:
		venvDir := filepath.Join(m.rootDir, string(spec.ID), spec.Version, "venv")
		if runtime.GOOS == "windows" {
			return filepath.Join(venvDir, "Scripts", spec.Command)
		}
		return filepath.Join(venvDir, "bin", spec.Command)
	default:
		return filepath.Join(m.rootDir, string(spec.ID), spec.Version, spec.Command)
	}
}

func platformKey() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

func binaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func specsFor(ids []ToolID) []ToolSpec {
	all := SupportedTools()
	out := make([]ToolSpec, 0, len(ids))
	for _, id := range ids {
		for _, spec := range all {
			if spec.ID == id {
				out = append(out, spec)
				break
			}
		}
	}
	return out
}

func detectVersion(ctx context.Context, command string, args []string) string {
	if strings.TrimSpace(command) == "" {
		return ""
	}
	versionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(versionCtx, command, args...)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.Split(strings.TrimSpace(string(output)), "\n")[0])
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func downloadFile(ctx context.Context, url string, destination string, expectedSHA256 string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("download %s returned %s", url, response.Status)
	}

	file, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("create %s: %w", destination, err)
	}
	defer file.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(file, hasher)
	if _, err := io.Copy(writer, response.Body); err != nil {
		return fmt.Errorf("write %s: %w", destination, err)
	}

	if strings.TrimSpace(expectedSHA256) != "" {
		actual := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(actual, expectedSHA256) {
			return fmt.Errorf("checksum mismatch for %s", filepath.Base(destination))
		}
	}
	return nil
}

func extractBinary(archivePath string, archiveType string, binaryName string, workDir string) (string, error) {
	switch archiveType {
	case "zip":
		return extractBinaryFromZip(archivePath, binaryName, workDir)
	case "tar.gz":
		return extractBinaryFromTarGz(archivePath, binaryName, workDir)
	default:
		return "", fmt.Errorf("unsupported archive type %q", archiveType)
	}
}

func extractBinaryFromZip(archivePath string, binaryName string, workDir string) (string, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("open archive %s: %w", archivePath, err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		if filepath.Base(file.Name) != binaryName {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return "", fmt.Errorf("open %s from archive: %w", binaryName, err)
		}
		defer rc.Close()

		targetPath := filepath.Join(workDir, binaryName)
		targetFile, err := os.Create(targetPath)
		if err != nil {
			return "", fmt.Errorf("create extracted binary: %w", err)
		}
		if _, err := io.Copy(targetFile, rc); err != nil {
			targetFile.Close()
			return "", fmt.Errorf("extract %s: %w", binaryName, err)
		}
		targetFile.Close()
		return targetPath, nil
	}

	return "", fmt.Errorf("%s was not found in %s", binaryName, filepath.Base(archivePath))
}

func extractBinaryFromTarGz(archivePath string, binaryName string, workDir string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("open archive %s: %w", archivePath, err)
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("open gzip %s: %w", archivePath, err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar archive %s: %w", archivePath, err)
		}
		if filepath.Base(header.Name) != binaryName {
			continue
		}

		targetPath := filepath.Join(workDir, binaryName)
		targetFile, err := os.Create(targetPath)
		if err != nil {
			return "", fmt.Errorf("create extracted binary: %w", err)
		}
		if _, err := io.Copy(targetFile, tr); err != nil {
			targetFile.Close()
			return "", fmt.Errorf("extract %s: %w", binaryName, err)
		}
		targetFile.Close()
		return targetPath, nil
	}

	return "", fmt.Errorf("%s was not found in %s", binaryName, filepath.Base(archivePath))
}

func copyExecutable(source string, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open %s: %w", source, err)
	}
	defer input.Close()

	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create directory for %s: %w", destination, err)
	}

	output, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("create %s: %w", destination, err)
	}
	defer output.Close()

	if _, err := io.Copy(output, input); err != nil {
		return fmt.Errorf("copy %s to %s: %w", source, destination, err)
	}

	mode := os.FileMode(0o755)
	if runtime.GOOS == "windows" {
		mode = 0o644
	}
	if err := os.Chmod(destination, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", destination, err)
	}

	return nil
}

type PythonRuntime struct {
	Command     string
	Args        []string
	DisplayName string
}

func findPython(ctx context.Context) (PythonRuntime, error) {
	candidates := []PythonRuntime{
		{Command: "py", Args: []string{"-3"}, DisplayName: "py -3"},
		{Command: "python3", DisplayName: "python3"},
		{Command: "python", DisplayName: "python"},
	}

	for _, candidate := range candidates {
		if _, err := exec.LookPath(candidate.Command); err != nil {
			continue
		}
		if versionOK(ctx, candidate) {
			return candidate, nil
		}
	}

	return PythonRuntime{}, fmt.Errorf("Semgrep auto-install requires Python 3.10+ (looked for py -3, python3, and python)")
}

func versionOK(ctx context.Context, runtime PythonRuntime) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	args := append(runtime.Args, "-c", "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')")
	cmd := exec.CommandContext(checkCtx, runtime.Command, args...)
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	version := strings.TrimSpace(string(output))
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}

	var major, minor int
	_, err = fmt.Sscanf(version, "%d.%d", &major, &minor)
	if err != nil {
		return false
	}
	return major > 3 || (major == 3 && minor >= 10)
}

func runCommand(ctx context.Context, log io.Writer, command string, args ...string) error {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = append(os.Environ(), "PIP_DISABLE_PIP_VERSION_CHECK=1")
	if log != nil {
		cmd.Stdout = log
		cmd.Stderr = log
	}
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func managedPythonPath(venvDir string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(venvDir, "Scripts", "python.exe")
	}
	return filepath.Join(venvDir, "bin", "python")
}

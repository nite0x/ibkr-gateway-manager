package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	installManifestFilename       = ".ibkr-gateway-manager-install.json"
	legacyInstallManifestFilename = ".traio-install.json"
)

type gatewayRelease struct {
	Version string
	URL     string
	SHA256  string
	Size    int64
}

var officialGatewayRelease = gatewayRelease{
	Version: "20230424154245",
	URL:     gatewayDownloadURL,
	SHA256:  "2f2d380b2f9424520ff5f9c11fe45e82ef39459329ac056258a3274bea6f76f9",
	Size:    10_542_956,
}

type gatewayInstallManifest struct {
	Version     string `json:"version"`
	Source      string `json:"source"`
	ArchiveSHA  string `json:"archive_sha256,omitempty"`
	InstalledAt string `json:"installed_at"`
	Verified    bool   `json:"verified"`
}

func installManifestPath(gatewayDir string) string {
	return filepath.Join(gatewayDir, installManifestFilename)
}

func rollbackGatewayDir(gatewayDir string) string {
	return gatewayDir + ".rollback"
}

func readInstallManifest(gatewayDir string) (gatewayInstallManifest, error) {
	data, err := os.ReadFile(installManifestPath(gatewayDir))
	if os.IsNotExist(err) {
		data, err = os.ReadFile(filepath.Join(gatewayDir, legacyInstallManifestFilename))
	}
	if err != nil {
		return gatewayInstallManifest{}, err
	}
	var manifest gatewayInstallManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return gatewayInstallManifest{}, err
	}
	return manifest, nil
}

func writeInstallManifest(gatewayDir string, manifest gatewayInstallManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(installManifestPath(gatewayDir), data, 0o600)
}

func (g *GatewayManager) adoptLegacyInstall() error {
	if _, err := readInstallManifest(g.config.GatewayDir); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read gateway install manifest: %w", err)
	}
	return writeInstallManifest(g.config.GatewayDir, gatewayInstallManifest{
		Version:     "legacy-adopted",
		Source:      "existing installation",
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
		Verified:    false,
	})
}

func (g *GatewayManager) installBundledAtomic(sourceDir string) error {
	stageRoot, payload, err := newGatewayStage(g.config.GatewayDir)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stageRoot)
	if err := copyDir(sourceDir, payload); err != nil {
		return fmt.Errorf("copy bundled gateway: %w", err)
	}
	manifest := gatewayInstallManifest{
		Version:     "bundled",
		Source:      "application bundle",
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
		Verified:    false,
	}
	if err := g.prepareStagedGateway(payload, manifest); err != nil {
		return err
	}
	return g.activateStagedGateway(payload)
}

func (g *GatewayManager) installVerifiedRelease(ctx context.Context) error {
	release := g.release
	if release.URL == "" || release.SHA256 == "" || release.Version == "" {
		return fmt.Errorf("gateway release manifest is incomplete")
	}
	stageRoot, payload, err := newGatewayStage(g.config.GatewayDir)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stageRoot)

	archive := filepath.Join(stageRoot, "clientportal.gw.zip")
	if err := g.downloadVerifiedRelease(ctx, release, archive); err != nil {
		return err
	}
	if err := unzip(archive, payload); err != nil {
		return fmt.Errorf("extract verified gateway: %w", err)
	}
	manifest := gatewayInstallManifest{
		Version:     release.Version,
		Source:      release.URL,
		ArchiveSHA:  strings.ToLower(release.SHA256),
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
		Verified:    true,
	}
	if err := g.prepareStagedGateway(payload, manifest); err != nil {
		return err
	}
	return g.activateStagedGateway(payload)
}

func newGatewayStage(gatewayDir string) (stageRoot, payload string, err error) {
	parent := filepath.Dir(filepath.Clean(gatewayDir))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", "", fmt.Errorf("create gateway parent: %w", err)
	}
	stageRoot, err = os.MkdirTemp(parent, ".ibkr-gateway-stage-")
	if err != nil {
		return "", "", fmt.Errorf("create gateway stage: %w", err)
	}
	if err := os.Chmod(stageRoot, 0o700); err != nil {
		os.RemoveAll(stageRoot)
		return "", "", err
	}
	payload = filepath.Join(stageRoot, "payload")
	if err := os.Mkdir(payload, 0o700); err != nil {
		os.RemoveAll(stageRoot)
		return "", "", err
	}
	return stageRoot, payload, nil
}

func (g *GatewayManager) prepareStagedGateway(payload string, manifest gatewayInstallManifest) error {
	if !gatewayInstalled(payload) {
		return fmt.Errorf("staged gateway is missing required startup files")
	}
	if err := preserveGatewayConfigs(g.config.GatewayDir, payload); err != nil {
		return fmt.Errorf("preserve instance configurations: %w", err)
	}
	if g.config.configFile() == "root/conf.yaml" {
		if err := patchGatewayConf(filepath.Join(payload, "root", "conf.yaml"), g.config); err != nil {
			return fmt.Errorf("configure staged gateway: %w", err)
		}
	}
	if err := writeInstallManifest(payload, manifest); err != nil {
		return fmt.Errorf("write install manifest: %w", err)
	}
	return secureGatewayRuntime(payload)
}

func (g *GatewayManager) activateStagedGateway(payload string) error {
	live := filepath.Clean(g.config.GatewayDir)
	backup := rollbackGatewayDir(live)
	hadLive := gatewayInstalled(live)
	if hadLive {
		if err := os.RemoveAll(backup); err != nil {
			return fmt.Errorf("remove previous rollback: %w", err)
		}
		if err := os.Rename(live, backup); err != nil {
			return fmt.Errorf("backup active gateway: %w", err)
		}
	}
	if err := os.Rename(payload, live); err != nil {
		if hadLive {
			_ = os.Rename(backup, live)
		}
		return fmt.Errorf("activate staged gateway: %w", err)
	}
	if err := secureGatewayRuntime(live); err != nil {
		if hadLive {
			_ = os.RemoveAll(live)
			_ = os.Rename(backup, live)
		}
		return fmt.Errorf("secure activated gateway: %w", err)
	}
	return nil
}

func (g *GatewayManager) swapWithRollback() error {
	live := filepath.Clean(g.config.GatewayDir)
	backup := rollbackGatewayDir(live)
	if !gatewayInstalled(backup) {
		return fmt.Errorf("no rollback gateway is available")
	}
	if err := preserveGatewayConfigs(live, backup); err != nil {
		return fmt.Errorf("preserve instance configurations: %w", err)
	}
	temporary := live + fmt.Sprintf(".swap-%d", time.Now().UnixNano())
	if err := os.Rename(live, temporary); err != nil {
		return fmt.Errorf("move active gateway for rollback: %w", err)
	}
	if err := os.Rename(backup, live); err != nil {
		_ = os.Rename(temporary, live)
		return fmt.Errorf("activate rollback gateway: %w", err)
	}
	if err := os.Rename(temporary, backup); err != nil {
		return fmt.Errorf("preserve replaced gateway: %w", err)
	}
	return secureGatewayRuntime(live)
}

func (g *GatewayManager) downloadVerifiedRelease(ctx context.Context, release gatewayRelease, destination string) error {
	client, err := gatewayDownloadClient(g.config.DownloadProxy)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, release.URL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download gateway release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download gateway release status %d", resp.StatusCode)
	}
	if release.Size > 0 && resp.ContentLength >= 0 && resp.ContentLength != release.Size {
		return fmt.Errorf("gateway release size mismatch: expected %d, got %d", release.Size, resp.ContentLength)
	}

	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	var body io.Reader = resp.Body
	if release.Size > 0 {
		body = io.LimitReader(resp.Body, release.Size+1)
	}
	written, copyErr := io.Copy(io.MultiWriter(out, hash), body)
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("download gateway release body: %w", copyErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if release.Size > 0 && written != release.Size {
		return fmt.Errorf("gateway release size mismatch: expected %d, got %d", release.Size, written)
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, release.SHA256) {
		return fmt.Errorf("gateway release SHA-256 mismatch: expected %s, got %s", release.SHA256, actual)
	}
	return nil
}

func gatewayDownloadClient(proxyURL string) (*http.Client, error) {
	transport := &http.Transport{}
	proxy := strings.TrimSpace(proxyURL)
	if proxy == "" {
		proxy = strings.TrimSpace(os.Getenv("HTTPS_PROXY"))
	}
	if proxy == "" {
		proxy = strings.TrimSpace(os.Getenv("HTTP_PROXY"))
	}
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("parse download proxy: %w", err)
		}
		transport.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Timeout: 5 * time.Minute, Transport: transport}, nil
}

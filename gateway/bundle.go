package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BundleOfficialRelease prepares an immutable image template using the same
// pinned URL, size and SHA-256 as runtime installs. It never creates an instance,
// patches user configuration, starts Java, or creates runtime credentials.
func BundleOfficialRelease(ctx context.Context, destination string) error {
	return bundleRelease(ctx, destination, officialGatewayRelease)
}

func bundleRelease(ctx context.Context, destination string, release gatewayRelease) error {
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return fmt.Errorf("bundle destination must not already exist: %s", destination)
	}
	stage, payload, err := newGatewayStage(destination)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	archive := filepath.Join(stage, "clientportal.gw.zip")
	downloader := &GatewayManager{}
	if err := downloader.downloadVerifiedRelease(ctx, release, archive); err != nil {
		return err
	}
	if err := unzip(archive, payload); err != nil {
		return err
	}
	if !gatewayInstalled(payload) {
		return fmt.Errorf("official Gateway archive is missing startup files")
	}
	if err := writeInstallManifest(payload, gatewayInstallManifest{
		Version: release.Version, Source: release.URL, ArchiveSHA: strings.ToLower(release.SHA256),
		Verified: true, InstalledAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return err
	}
	return os.Rename(payload, destination)
}

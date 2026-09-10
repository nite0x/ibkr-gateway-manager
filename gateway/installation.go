package gateway

import (
	"context"
	"fmt"
	"log"
	"os"
)

func (g *GatewayManager) EnsureInstalled(ctx context.Context) error {
	unlock, err := g.lockInstallation(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return g.ensureInstalled(ctx)
}

func (g *GatewayManager) ensureInstalled(ctx context.Context) error {
	if err := os.MkdirAll(g.config.stateDir(), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(g.config.stateDir(), 0o700); err != nil {
		return err
	}
	if gatewayInstalled(g.config.GatewayDir) {
		if err := g.adoptLegacyInstall(); err != nil {
			return err
		}
		if err := g.ensureGatewayConf(); err != nil {
			return err
		}
		return g.secureRuntimePermissions()
	}

	if g.config.BundledGatewayDir != "" {
		if !gatewayInstalled(g.config.BundledGatewayDir) {
			return fmt.Errorf("bundled_gateway_dir %q is not a valid Gateway installation; refusing to download a different version", g.config.BundledGatewayDir)
		}
		log.Printf("[IBKR] installing gateway from bundled dir %s", g.config.BundledGatewayDir)
		if err := g.installBundledAtomic(g.config.BundledGatewayDir); err != nil {
			return err
		}
		g.audit("gateway.install", "success", "installed from application bundle")
		log.Printf("[IBKR] gateway installed at %s", g.config.GatewayDir)
		return g.ensureGatewayConf()
	}

	log.Printf("[IBKR] downloading verified gateway release %s", g.release.Version)
	if err := g.installVerifiedRelease(ctx); err != nil {
		return err
	}
	g.audit("gateway.install", "success", "installed verified release "+g.release.Version)
	log.Printf("[IBKR] gateway installed at %s", g.config.GatewayDir)
	return g.ensureGatewayConf()
}

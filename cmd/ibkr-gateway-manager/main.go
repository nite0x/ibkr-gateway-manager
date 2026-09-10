package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nite0x/ibkr-gateway-manager/gateway"
	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
	"github.com/nite0x/ibkr-gateway-manager/internal/localtls"
	"github.com/nite0x/ibkr-gateway-manager/internal/service"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	defaultPath, err := defaultConfigPath()
	if err != nil {
		return err
	}
	configPath := flag.String("config", defaultPath, "path to the JSON configuration file")
	exportCA := flag.Bool("export-local-ca", false, "print the existing public local CA certificate and exit (never exports private keys)")
	tlsStatus := flag.Bool("local-tls-status", false, "print existing local certificate metadata as JSON and exit")
	flag.Parse()
	if *exportCA || *tlsStatus {
		status, ca, err := localtls.Inspect(filepath.Join(filepath.Dir(*configPath), "tls"))
		if err != nil {
			return fmt.Errorf("read local TLS (start with IBKR_GATEWAY_LOCAL_TLS=true first): %w", err)
		}
		if *exportCA {
			_, err = os.Stdout.Write(ca)
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(status)
	}

	cfg, err := appconfig.LoadOrCreate(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	handler, err := service.NewRegistry(*configPath, cfg, func(cfg gateway.Config) service.Gateway {
		return gateway.NewGatewayManager(cfg)
	})
	if err != nil {
		return err
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := handler.StartProxyListeners(); err != nil {
		return err
	}
	handler.StartConfigured(rootCtx)

	var managerServer *http.Server
	if cfg.SharedProxyListenAddr == "" {
		managerServer = &http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       90 * time.Second,
		}
		errCh := make(chan error, 1)
		go func() {
			log.Printf("IBKR Gateway Manager listening at %s", cfg.PublicURL)
			errCh <- managerServer.ListenAndServe()
		}()
		select {
		case <-rootCtx.Done():
		case err := <-errCh:
			if err != nil && err != http.ErrServerClosed {
				return err
			}
		}
	} else {
		log.Printf("IBKR Gateway Manager available through shared origin %s", cfg.PublicURL)
		<-rootCtx.Done()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if managerServer != nil {
		_ = managerServer.Shutdown(shutdownCtx)
	}
	return handler.Shutdown()
}

func defaultConfigPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "ibkr-gateway-manager", "config.json"), nil
}

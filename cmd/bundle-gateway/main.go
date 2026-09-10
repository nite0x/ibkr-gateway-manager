// bundle-gateway is a build-time tool, not part of the final runtime image.
package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/nite0x/ibkr-gateway-manager/gateway"
)

func main() {
	output := flag.String("output", "", "new directory for the verified official Gateway distribution")
	flag.Parse()
	if *output == "" {
		log.Fatal("-output is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := gateway.BundleOfficialRelease(ctx, *output); err != nil {
		log.Fatal(err)
	}
}

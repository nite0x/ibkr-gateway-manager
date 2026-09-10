# Third-party software

IBKR Gateway Manager is an independent community project, licensed under the
[MIT License](LICENSE). It is not affiliated with or endorsed by Interactive Brokers.

## Go binary

The Manager binary includes the following BSD-3-Clause components. Their license
texts are included with source and in `/usr/local/share/ibkr-gateway-manager/licenses`
in the Docker image:

| Component | License text |
|---|---|
| Go standard library | [Go license](licenses/go.txt) |
| github.com/gofrs/flock | [flock license](licenses/gofrs-flock.txt) |
| golang.org/x/sys | [x/sys license](licenses/golang-x-sys.txt) |

## Container runtime

The Docker image uses Eclipse Temurin OpenJDK 17 and Ubuntu packages. Their own
licenses and notices remain in the base image (including the JRE `legal` directory
and `/usr/share/doc`). They are not relicensed under the Manager's MIT license.

## Interactive Brokers Client Portal Gateway

The default Docker image does not include the IBKR Gateway distribution. On first
instance start, the Manager downloads it from Interactive Brokers and verifies the
pinned archive's size and SHA-256 before installation into the user's data volume.
The Gateway and its dependencies remain subject to their respective terms.

See IBKR's [installation documentation](https://www.interactivebrokers.com/docs/web-api/authentication/cpgw/installation-authentication)
and the notices supplied with the downloaded software. Users are responsible for
ensuring their use is permitted by the applicable IBKR terms. A downloadable archive
does not, by itself, establish permission to redistribute it.

The optional `bundled_gateway_dir` setting and `cmd/bundle-gateway` utility support
user-provided installations. They do not grant redistribution rights. Do not publish
images or archives containing the Gateway without confirming those rights.

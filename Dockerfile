FROM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ibkr-gateway-manager ./cmd/ibkr-gateway-manager

FROM eclipse-temurin:17-jre-jammy
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl lsof \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 10001 gateway
RUN install -d -o gateway -g gateway -m 0700 /home/gateway/.config/ibkr-gateway-manager
# Gateway is downloaded from IBKR on first instance start, not redistributed here.
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/local/share/ibkr-gateway-manager/
COPY licenses/ /usr/local/share/ibkr-gateway-manager/licenses/
USER gateway
COPY --from=build /out/ibkr-gateway-manager /usr/local/bin/ibkr-gateway-manager
COPY scripts/trust-local-tls-macos.sh /usr/local/share/ibkr-gateway-manager/trust-local-tls-macos.sh
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/ibkr-gateway-manager"]

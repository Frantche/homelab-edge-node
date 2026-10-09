FROM golang:1.26.8-alpine3.23 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/edge-manager ./cmd/edge-manager \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/edge-kubernetes-controller ./cmd/edge-kubernetes-controller

FROM alpine:3.24.2
RUN apk add --no-cache ca-certificates nftables
COPY --from=build /out/edge-manager /edge-manager
COPY --from=build /out/edge-kubernetes-controller /edge-kubernetes-controller

WORKDIR /var/lib/homelab-edge-node
ENTRYPOINT ["/edge-manager"]

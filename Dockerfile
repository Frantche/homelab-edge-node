FROM golang:1.27.4-alpine3.23@sha256:f70850ef6ce341e8b6427f677049145d63c0b7ce002d4d7e3d464828b1b96dcd AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/edge-manager ./cmd/edge-manager \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/edge-kubernetes-controller ./cmd/edge-kubernetes-controller

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache ca-certificates nftables
COPY --from=build /out/edge-manager /edge-manager
COPY --from=build /out/edge-kubernetes-controller /edge-kubernetes-controller

WORKDIR /var/lib/homelab-edge-node
ENTRYPOINT ["/edge-manager"]

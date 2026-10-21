FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/familychat-push-gateway ./cmd/familychat-push-gateway

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/familychat-push-gateway /usr/local/bin/familychat-push-gateway
USER 10001:10001
EXPOSE 9443
ENTRYPOINT ["/usr/local/bin/familychat-push-gateway"]

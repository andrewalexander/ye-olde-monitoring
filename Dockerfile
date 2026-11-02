# Local/container image: both binaries, static, on distroless (no shell).
#   docker build -t dnscount .
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/dnscount ./cmd/dnscount \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/example-app ./examples/app \
 && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/dnscount /out/example-app /usr/local/bin/
# A fresh named volume mounted here inherits this ownership.
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENV DNSCOUNT_DB=/data/dnscount.db
USER nonroot
ENTRYPOINT ["/usr/local/bin/dnscount"]
CMD ["serve"]

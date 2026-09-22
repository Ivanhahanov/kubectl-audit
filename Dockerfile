# Multi-target Dockerfile for this repo's four binaries — build one at a
# time with `docker build --target <audit|server|worker|mcp> -t <tag> .`.
# All four are the same static (CGO_ENABLED=0) build already used by `make
# build`, just packaged for in-cluster (kubectl-audit-server/-worker
# Deployment) use instead of a local binary.
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/kubectl-audit ./cmd/kubectl-audit
RUN CGO_ENABLED=0 go build -o /out/kubectl-audit-server ./cmd/kubectl-audit-server
RUN CGO_ENABLED=0 go build -o /out/kubectl-audit-worker ./cmd/kubectl-audit-worker
RUN CGO_ENABLED=0 go build -o /out/kubectl-audit-mcp ./cmd/kubectl-audit-mcp

FROM gcr.io/distroless/static-debian12:nonroot AS audit
COPY --from=builder /out/kubectl-audit /usr/local/bin/kubectl-audit
COPY --from=builder /out/kubectl-audit-mcp /usr/local/bin/kubectl-audit-mcp
ENTRYPOINT ["/usr/local/bin/kubectl-audit"]

FROM gcr.io/distroless/static-debian12:nonroot AS server
COPY --from=builder /out/kubectl-audit-server /usr/local/bin/kubectl-audit-server
ENTRYPOINT ["/usr/local/bin/kubectl-audit-server"]

FROM gcr.io/distroless/static-debian12:nonroot AS worker
COPY --from=builder /out/kubectl-audit-worker /usr/local/bin/kubectl-audit-worker
ENTRYPOINT ["/usr/local/bin/kubectl-audit-worker"]

FROM gcr.io/distroless/static-debian12:nonroot AS mcp
COPY --from=builder /out/kubectl-audit /usr/local/bin/kubectl-audit
COPY --from=builder /out/kubectl-audit-mcp /usr/local/bin/kubectl-audit-mcp
ENTRYPOINT ["/usr/local/bin/kubectl-audit-mcp"]

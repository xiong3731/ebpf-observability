# 构建：docker build -t uhub.service.ucloud.cn/aigc-serving-public/ebpf-obs-agent:<tag> .
FROM golang:1.26-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm libbpf-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go generate ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /exporter .

FROM gcr.io/distroless/static-debian12
COPY --from=build /exporter /exporter
ENTRYPOINT ["/exporter"]

# 构建 ebpf-obs-agent 镜像。
#
# 注意两件事：
#   1. go.mod 要求 go 1.25.0，所以 builder 镜像不能用更老的 tag
#   2. 构建阶段必须重新跑 bpf2go，不能依赖仓库里提交的 bpf_bpfel.o
#      （那个文件被 Makefile 之类的工具 truncate 过，是不可信的中间产物）
#
# 用法（在仓库根目录执行）：
#   docker build -f deploy/Dockerfile -t <你的仓库>/ebpf-obs-agent:dev .

# ── 构建阶段 ────────────────────────────────────────────────
FROM golang:1.25-bookworm AS builder

# bpf2go 会去调 clang 编译 .c，需要 llvm 工具链
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        git \
        make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# 先只拷依赖描述，让 go mod download 这层能被缓存
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# 重新生成 BPF 对象和 Go 绑定
RUN go generate ./...

# CGO_ENABLED=0 才能编出静态二进制，
# 这样 hostPath 版本可以随便塞进任何有 libc 的镜像里跑
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agent .

# ── 运行阶段 ────────────────────────────────────────────────
# 用完整发行版而不是 distroless，是为了能 exec 进去跑 bpftool / ip 排查问题。
# 学习阶段这个便利性比镜像体积重要。
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        bpftool \
        iproute2 \
        ca-certificates \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/agent /agent

ENTRYPOINT ["/agent"]

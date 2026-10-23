#!/usr/bin/env bash
#
# 开发循环：构建 → 分发到 worker → 重启 DaemonSet → 看日志
#
# 改完代码跑这个就行，几秒钟。比走镜像仓库快两个数量级。
#
# 用法：
#   hack/dev.sh                    构建仓库根目录的 main 包
#   hack/dev.sh ./cmd/agent        构建指定包（Phase 1 之后大概率用这个）
#   NO_DEPLOY=1 hack/dev.sh        只构建，不分发（本地验证编译错误）
#   NO_RESTART=1 hack/dev.sh       构建 + 分发，但不重启 DaemonSet
#                                  （Step 1 观察期用：exec 进 pod 手动跑新二进制）
#   NODES="10.13.28.93" hack/dev.sh   只推到指定节点
#
set -euo pipefail

NODES="${NODES:-10.13.177.131 10.13.28.93 10.13.48.209}"
REMOTE_DIR="${REMOTE_DIR:-/opt/ebpf-obs}"
NS="${NS:-ebpf-obs}"
DS="${DS:-ebpf-obs-agent}"
PKG="${1:-.}"

# 无论从哪调用都回到仓库根目录
cd "$(dirname "$0")/.."

echo "==> 构建 $PKG"
# CGO_ENABLED=0 才编得出静态二进制，这样塞进任何容器镜像都能跑
CGO_ENABLED=0 go build -trimpath -o agent "$PKG"

if [[ "${NO_DEPLOY:-0}" == "1" ]]; then
    echo "==> NO_DEPLOY=1，跳过分发"
    exit 0
fi

for ip in $NODES; do
    echo "==> 分发到 $ip"
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR "root@$ip" "mkdir -p $REMOTE_DIR"
    # 必须先传成 .new 再 mv，不能直接覆盖：
    # 容器正在执行 /opt/ebpf-obs/agent，内核会拒绝写入（ETXTBSY "Text file busy"）。
    # mv 是重命名目录项，运行中的进程继续持有旧 inode，不受影响。
    scp -o StrictHostKeyChecking=no -o LogLevel=ERROR -q agent "root@$ip:$REMOTE_DIR/agent.new"
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR "root@$ip" "mv -f $REMOTE_DIR/agent.new $REMOTE_DIR/agent"
done

echo "==> 重启 DaemonSet"
if [[ "${NO_RESTART:-0}" == "1" ]]; then
    echo "==> NO_RESTART=1，跳过分发后的重启"
    echo "    在 pod 里手动跑：kubectl exec -it -n $NS ds/$DS -- $REMOTE_DIR/agent"
    exit 0
fi

kubectl rollout restart "ds/$DS" -n "$NS" >/dev/null
kubectl rollout status "ds/$DS" -n "$NS" --timeout=120s

echo
echo "==> 最近日志（持续跟踪：kubectl logs -f -n $NS -l app.kubernetes.io/name=$DS --prefix）"
kubectl logs -n "$NS" -l "app.kubernetes.io/name=$DS" --tail=30 --prefix

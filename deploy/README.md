# deploy

ebpf-obs-agent 的部署清单。对应 README 主文档的 **Phase 0**。

**当前只有 namespace + DaemonSet。** 按「怎么简单怎么来」的原则，暂时不加 RBAC 和 ConfigMap：

| 什么时候需要 | 加什么 |
|---|---|
| Phase 0（现在） | 一个 namespace + 一个 DaemonSet，够了 |
| Phase 2 过滤绑定 | ConfigMap（采集配置的载体） |
| Phase 4 语义绑定 | ServiceAccount + ClusterRole（读 Pod/Namespace） |

现在 agent 只用 netlink 和 eBPF，**完全不碰 k8s API**，所以用 default ServiceAccount 就够了。

---

## 集群事实（2026-10-13 实测）

这些不是猜测，是连上集群和 SSH 到节点实际查出来的。**改代码前先看这一节**，里面几条会直接决定 Phase 1/2 怎么写。

| 项 | 值 | 影响 |
|---|---|---|
| 集群 | UCloud UK8S，k8s `v1.34.5-ucloud.1` | 托管控制面，master 上不跑工作负载 |
| 节点 | 6 台：3 master（taint + unschedulable）+ 3 worker | DaemonSet 只落 worker |
| worker | `10.13.177.131` / `10.13.28.93` / `10.13.48.209` | |
| 内核 | `6.8.0-31-generic`（全部节点，与本机一致） | **支持 TCX**（需 6.6+），不用写 clsact 回退 |
| BTF | `/sys/kernel/btf/vmlinux` 存在 | CO-RE 可用 |
| CNI | **uk8s-cni-vpc**（`/opt/cni/bin/cnivpc`） | 见下方「坑」 |
| 容器运行时 | containerd 2.1.5 | |
| PSA | 所有 namespace 无 `pod-security` 标签 | privileged 放行，不会被拦 |

### 四条会影响代码的发现

**1. Pod 的 veth 名字是 `ucni*@if3`，不是 `veth*`**

```
ucni015abd619c5@if3    ba:e7:27:a1:17:d1    link-netns cni-0fc13395-...
```

所以**不要按名字前缀筛**。retina 的做法是按类型筛（`link.Type() == "veth"`），
在这个集群里同样有效——`ip -d link show` 确认了这些链接的类型就是 `veth`。

**2. netns 名字 `cni-<随机hex>` **不是** Pod UID**

对照过该节点上全部 Pod 的 UID，一个都对不上。这些 hex 也不是合法 UUID
（版本位是 6/a，不是 1-5），是 CNI 自己生成的随机串。

> **这条很重要**：它意味着**你无法从 veth 反查 Pod**。
> 想靠「veth → netns → 读 Pod 名」这条路走不通，只能走 k8s API。
>
> 这也正好印证了 retina 的设计：**Layer 0 只管挂载和清理，从不试图知道
> veth 属于哪个 Pod**。身份解析全部留给 Layer 2 的 IP 反查。
> 理解了这点，三层绑定的边界就清楚了。

**3. Pod IP 和节点 IP 在同一个 VPC 网段**

Pod IP 形如 `10.13.189.121`，节点 IP 是 `10.13.177.131`——**同一个网段**。
这是 VPC CNI 的特点（Pod 直接用 VPC 的 IP，不做 overlay）。

所以单看一个 IP，**你无法判断它是节点还是 Pod**，必须查 k8s。
这比 overlay CNI（Pod 在独立 CIDR 里）更需要 Layer 2。

**4. 集群里有真实的 hostNetwork Pod**

```
cni-vpc-ipamd-rvr27                          10.13.177.131   ← 等于节点 IP
csi-udisk-cxzzt                              10.13.177.131
csi-ufile-2phfw                              10.13.177.131
uk8s-monitor-prometheus-node-exporter-hltwm  10.13.177.131
```

Phase 4 要用 `status.podIP != $NODE_IP` 排除 hostNetwork Pod，
**这些就是你现成的测试样本**——不排除的话，它们会污染 IP → Pod 索引，
把整个节点的流量都算到某个 DaemonSet Pod 头上。

### 其他

- 默认出接口是 **eth0**，但它不是一张普通网卡，是 **net_failover master**：

  | 接口 | 角色 | 驱动 | 说明 |
  |---|---|---|---|
  | eth0 | master | virtio_net | 业务身份：IP、路由、MAC 都在这里，VF 故障切换时不变 |
  | eth1 | **standby** | virtio_net | altname `ens4nsby`（nsby = net_failover standby），回退路径，平时无流量 |
  | eth2 | **primary** | mlx5_core | SR-IOV VF，硬件加速，实际承载所有流量 |

  三块网卡 MAC 相同是 net_failover 的设计（对外保持统一身份），
  **不是**报文从三张网卡各发一遍。eth0 的计数来自当前活跃的 primary。
- veth 的 **MTU 是 1452**（VPC 封装开销），不是 1500
- 集群现用镜像仓库：`uhub.service.ucloud.cn`，拉取凭据 secret 名为 `uhub-aigc`
- **本机 docker 未登录任何仓库**，push 前需要先 `docker login`
- 三个 worker 已装好 **bpftool v7.4.0**。装的时候有个坑：`bpftool` 是虚拟包，
  且 apt 里只有 `linux-tools-6.8.0-136-generic`，而运行内核是 `6.8.0-31`，
  wrapper 按运行内核找会报 `bpftool not found for kernel 6.8.0-31`。
  **要装版本对应的那个包**：

  ```bash
  apt-get install -y linux-tools-$(uname -r)-generic   # 6.8.0-31-generic
  ```

---

## 两条路径，怎么选

| | hostPath 版 | 镜像版 |
|---|---|---|
| 文件 | `daemonset-hostpath.yaml` | `daemonset.yaml` |
| 迭代一次 | `go build` + `scp` + 重启，**几秒** | `docker build` + `push` + rollout，**几分钟** |
| 前置条件 | 能 SSH 到节点 | 有仓库 push 权限 |
| 适用 | **Phase 1~4 开发期** | 跑通后、或给别人部署 |

**开发期用 hostPath。** 你接下来会改几十次代码，这个差别是决定性的。
两条路的 pod 名字相同（`ebpf-obs-agent`），切换时先删掉另一个。

---

## 快速开始（hostPath 路径）

### 1. 创建 namespace

```bash
kubectl apply -f deploy/namespace.yaml
```

### 2. 构建并分发二进制

```bash
# 静态编译（CGO_ENABLED=0 才能塞进任意镜像跑）
CGO_ENABLED=0 go build -trimpath -o agent .

# 三个 worker 各推一份
for ip in 10.13.177.131 10.13.28.93 10.13.48.209; do
  ssh root@$ip 'mkdir -p /opt/ebpf-obs'
  scp agent root@$ip:/opt/ebpf-obs/agent
done
```

### 3. 部署

```bash
kubectl apply -f deploy/daemonset-hostpath.yaml
```

### 4. 重新部署（改代码后）

```bash
CGO_ENABLED=0 go build -trimpath -o agent .
for ip in 10.13.177.131 10.13.28.93 10.13.48.209; do
  scp agent root@$ip:/opt/ebpf-obs/agent
done
kubectl rollout restart ds/ebpf-obs-agent -n ebpf-obs
```

---

## 镜像路径（暂时不用）

```bash
# 1. 登录仓库（本机还没登录过）
docker login uhub.service.ucloud.cn

# 2. 构建（把 CHANGE_ME 换成你有 push 权限的项目名）
docker build -f deploy/Dockerfile -t uhub.service.ucloud.cn/CHANGE_ME/ebpf-obs-agent:dev .

# 3. 推送
docker push uhub.service.ucloud.cn/CHANGE_ME/ebpf-obs-agent:dev

# 4. 复制拉取凭据到新 namespace
#    secret 是 namespace 级的，集群里现有的 uhub-aigc 在别的 namespace，这里没有
kubectl get secret uhub-aigc -n default -o yaml \
  | sed 's/namespace: default/namespace: ebpf-obs/' \
  | kubectl apply -f -

# 5. 改 daemonset.yaml 里的 image 字段，然后部署
kubectl apply -f deploy/daemonset.yaml
```

> **base 镜像的坑**：Dockerfile 用了 `golang:1.25-bookworm` 和 `ubuntu:24.04`，
> 都来自 docker.io。国内网络可能拉不动——如果卡住，看 uhub 上有没有对应的
> 镜像可以换。这一步卡住很常见，别怀疑自己。

---

## Phase 0 验收清单

- [ ] `kubectl get ds -n ebpf-obs` 显示 3/3 READY（只落 worker 才对）
- [ ] `kubectl logs -n ebpf-obs ds/ebpf-obs-agent` 打印出的是**宿主机**网卡
      （能看到 `eth0/eth1/eth2` 和一堆 `ucni*`，而不是容器里那个只有 `eth0` 的网络）
- [ ] `kubectl get pods -n ebpf-obs -o wide` 的 IP 等于节点 IP（验证 hostNetwork 生效）
- [ ] 进节点执行 `bpftool prog list` 能看到加载的程序
- [ ] 删掉 DaemonSet 后程序自动卸载（bpf_link 引用计数归零，节点上 `bpftool prog list` 里消失）

进 pod 里排查：

```bash
kubectl exec -it -n ebpf-obs ds/ebpf-obs-agent -- bash
# 镜像里装了 bpftool / ip / tcpdump，就是为了这个
bpftool prog list
ip -br link | head -20        # 应该看到宿主机的所有网卡
cat /sys/kernel/debug/tracing/trace_pipe   # bpf_printk 输出
```

---

## 这个集群特有的坑

**master 节点上不会有 agent。** master 带 `node-role.kubernetes.io/master`
和 `node.kubernetes.io/unschedulable` 两个 taint。manifest 里额外写了
nodeAffinity 排除 `control-plane` 角色，是为了意图清晰。
想连 master 一起观测，删掉那段 affinity 并给 taint 加 toleration。

**`/opt/ebpf-obs` 目录不会自动创建**，scp 前要先 `mkdir -p`，
否则 hostPath 挂载会因为 `type: Directory` 找不到路径而失败。

**清理：**

```bash
kubectl delete -f deploy/daemonset-hostpath.yaml
kubectl delete -f deploy/namespace.yaml     # 会连带删掉 namespace 里所有东西
```

**关于 `privileged: true`**：这是学习期的省事做法。
跑通之后可以收紧成只加需要的 capability：

```yaml
securityContext:
  capabilities:
    add: ["BPF", "NET_ADMIN", "PERFMON", "SYS_RESOURCE"]
```

不过 `SYS_ADMIN` 在某些内核上仍然需要（挂 bpffs 等），收紧时以实测为准。

---

## 和 retina 的对照

| 本项目 | retina |
|---|---|
| `deploy/daemonset-hostpath.yaml` | `deploy/` 下的 helm chart |
| （Phase 2 会加）ConfigMap | `MetricsConfiguration` CRD + `retina.sh` 注解 |
| （Phase 4 会加）ClusterRole | retina 的 ClusterRole（它还额外需要 CRD 权限） |

retina 的 DaemonSet 同样用 `hostNetwork: true` + privileged，
这是所有节点级 eBPF 观测组件的共同形态，不是偷懒。

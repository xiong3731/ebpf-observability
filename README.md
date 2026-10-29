# ebpf-observability

用 Go + C 复刻 [retina](https://github.com/microsoft/retina) 的**数据面绑定机制**，跑在真实 Kubernetes 集群上。

目标是一句话：**让一个包从内核里出来时，能回答「它是谁的」。**

> 本项目是学习项目。metrics exporter 和 CRD 不在范围内：结果直接打到终端。
> **默认全量采集，归类在用户态完成**；内核侧过滤是可选的优化手段，不是前提。

---

## 1. 要复刻的是什么

retina 做网络可观测性，最核心的机制是三层「绑定」。这三层性质完全不同，混在一起想就会糊涂：

| 层 | 绑定什么 | 用什么做 | 在本项目里的位置 |
|---|---|---|---|
| **Layer 0 接口绑定** | 内核接口 ↔ Pod netns | netlink dump + diff | 主线，必需 |
| **Layer 1 过滤绑定** | k8s 选择器 → IP 白名单 | LPM_TRIE map | **可选**，高流量时的降载手段 |
| **Layer 2 语义绑定** | IP → workload 身份 | informer + 内存索引 | **主线，核心** |

**最重要的一条结论：eBPF 侧完全不知道 Kubernetes 的存在。** 事件结构体里只有五元组，所谓"绑定"，join key 就是 IP——内核侧用 IP 做开关（如果开启了过滤），用户态用 IP 做身份反查。

**第二重要的一条结论：先采集，后归类。**

不在内核侧预先筛选，而是把节点上能看到的流量全部采集出来，再在用户态用 k8s 元数据回答「这是谁的」。理由：

1. **筛选要求你事先知道关心谁，归类不需要。** 新上线的服务、临时排查的流量，都可能在规则之外。
2. **被内核过滤掉的流量无法补回。** 归类失败至少还保留了五元组，可以事后分析或写兜底规则。
3. **过滤是优化，不是观测模型的一部分。** 它解决的是"流量太大、采集成本太高"，而不是"如何知道包属于谁"。

所以本项目的顺序是：接口绑定 → 全量事件 → 语义归类 → （可选）兜底规则与降载。Layer 1 仍然会实现，但放在最后，作为可选项。

### 和你已有的 TOA 工作是同一个问题

TOA 解决的是「NLB 做了 FullNAT，源 IP 变成了 NLB 的 IP，怎么找回真实客户端」。
Layer 2 解决的是「包出来了，怎么知道它是哪个 Pod 的」。

两者都是**身份解析**：一个从 TCP Option 里把身份捞回来，一个从 k8s 元数据里把身份查出来。现有代码里 `flow_key` / `toa_map` 的设计思路可以延续，只是身份的来源多了一个。

---

## 2. 环境与前提

| 项 | 状态 | 说明 |
|---|---|---|
| Go | 1.27.1 ✓ | |
| clang | 18.1.3 ✓ | bpf2go 依赖 |
| llvm-objdump | 18 ✓ | 看反汇编 |
| bpftool | 三个 worker 已装 ✓ | 调试 `prog list` / `net show` / `map dump` 必需 |
| 内核（本机） | 6.8.0-31 ✓ | TCX 需要 6.6+ |
| 内核（集群节点） | 6.8.0-31 ✓ | 与本机一致，**TCX 可用**，暂无回退需求 |
| BTF（集群节点） | `/sys/kernel/btf/vmlinux` 存在 ✓ | CO-RE 可用 |
| Docker | 29.1.3 ✓ | 镜像版路径用；本机未登录仓库 |
| kubectl | ✓ | 已接入 kubeconfig |
| 集群 | UCloud UK8S `v1.34.5`，6 节点 | 3 master（taint+unschedulable）+ 3 worker |
| CNI | uk8s-cni-vpc | **路由模式，无网桥**；Pod 的 veth 叫 `ucni*` |

详细集群事实（含 net_failover 网卡拓扑、hostNetwork Pod 样本）见 [deploy/README.md](deploy/README.md)。

### 首次构建：生成 BPF 文件

以下文件由工具生成，不提交 Git：

- `bpf/vmlinux.h`：从 Linux 内核 BTF 导出的 C 类型定义。
- 根目录和 `cmd/agent/` 下的 `bpf_bpfel.go`、`bpf_bpfel.o`：bpf2go 生成的 Go 绑定和 BPF 对象。

在仓库根目录执行，先生成头文件，再生成绑定，最后编译：

```bash
# 前提：已安装 Go、clang、LLVM、bpftool 和 libbpf 开发头文件。
# Ubuntu/Debian 的 libbpf 头文件由 libbpf-dev 提供。
# 需要在具有内核 BTF 的 Linux 环境执行。
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# 同时生成根目录练习入口和 cmd/agent 的 BPF 对象与 Go 绑定。
go generate ./...

# 编译集群 agent。
CGO_ENABLED=0 go build -trimpath -o agent ./cmd/agent
```

本机没有 `/sys/kernel/btf/vmlinux` 时，可从目标 Linux 节点复制 BTF 文件到本地，
再将上面命令中的文件路径替换为复制后的路径。
修改 `bpf/flow.bpf.c` 后，需要重新执行 `go generate ./...`，再编译 Go 程序。
构建 Docker 镜像前也需要先生成 `bpf/vmlinux.h`；当前 Dockerfile 会在镜像内重新生成 bpf2go 文件。

### 集群事实（已实测确认）

| 事实 | 值 | 对设计的影响 |
|---|---|---|
| 节点内核 | 6.8.0-31（全部节点） | TCX 可用，**暂不需要** clsact 回退 |
| BTF | 存在 | CO-RE 可用 |
| CNI 模式 | **路由，无网桥** | veth 的 `master` 为空，不用担心网桥层的重复计数 |
| veth 命名 | `ucni*@if3` | 只能按 `Type()=="veth"` 筛，**不能按名字前缀** |
| 节点网卡 | **net_failover**：eth0(master) + eth1(standby) + eth2(VF) | 靠 `MasterIndex != 0` 跳过 slave |

> **关于 TCX**：它是内核 6.6+ 的新式 tc 挂载，不需要 `tc` 命令、不需要 clsact qdisc，
> 因此 **`tc filter show` 看不到它，只有 `bpftool net show` 能看到**。
> 本集群用不上回退路径，但换到老内核的环境就需要——
> retina 两条都实现了，是很好的对照阅读材料：
> - TCX 路径 `pkg/plugin/packetparser/packetparser_linux.go:598` `attachViaTCX`
> - 传统路径 `:651` `attachViaTC`
> - 选择逻辑 `:586` `createQdiscAndAttach`

---

## 3. 目标架构

```text
   ┌─────────────────────────────────────────────────────────────┐
   │ 数据面（全量采集，不做 k8s 筛选）                              │
   │   tc ingress/egress 挂在 veth(每个 Pod) + eth0(节点)          │
   │   解析 → flow 表聚合 → ringbuf 上报事件（五元组 + 方向 + TOA）  │
   └───────────────────────────┬─────────────────────────────────┘
                               │ 结构化事件（所有流量）
   ┌───────────────────────────▼─────────────────────────────────┐
   │ Layer 2  语义绑定（纯用户态）                                  │
   │   informer: 本节点 Pod / Namespace / owner(Pod→RS→Deployment) │
   │   cache:    IP → {pod, workload, labels}                     │
   │   enricher: flow + 元数据 → 打印到终端                        │
   │   未命中:   兜底规则（可选）→ 仍然未命中则标 unknown            │
   └───────────────────────────▲─────────────────────────────────┘
                               │
   ┌───────────────────────────┴─────────────────────────────────┐
   │ Layer 0  接口绑定                                             │
   │   veth 发现(netlink) → diff → 广播事件 → 挂载/清理 tc 程序     │
   └───────────────────────────▲─────────────────────────────────┘
                               │
   ┌───────────────────────────┴─────────────────────────────────┐
   │ netlink: 宿主机上的接口拓扑                                    │
   └─────────────────────────────────────────────────────────────┘

   可选（Phase 4）：Layer 1 过滤 —— 流量太大时用 LPM_TRIE 在内核侧降载
```

---

## 4. 现状盘点

TOA 那条线已经走完 4 个阶段，这些**都是数据面的地基，直接复用**：

- [x] 最小 TC 程序：`bpf_printk` + 加载 + TCX 挂载
- [x] 用 map 计数（包数/字节数），Go 每秒读一次
- [x] 解析 Ethernet → IPv4 → TCP 头，按五元组统计
- [x] 解析 TCP Option 中的 TOA，写入 LRU_HASH
- [ ] FIN/RST 清理、NLB 网段校验、ringbuf 上报事件
- [ ] 追踪类入门：tracepoint `sched/sched_process_exec`

**已经具备的能力**（后面直接拿来用）：
- bpf2go 工具链跑通了
- `flow_key` 五元组 + 方向合并的设计
- `toa_client` 结构体（注意里面 `pad` 字段——你已经踩过 padding 的坑）
- LRU_HASH 的用法、`__sync_fetch_and_add` 原子累加

**还缺的**（本项目要补的）：
- 挂载目标写死 `eth0` → 要变成「发现所有 Pod veth」
- 数据只能轮询 map → 要变成 ringbuf 实时事件
- 不知道包属于谁 → 要接入 k8s 元数据

---

## 5. 目录规划

刻意对齐 retina 的布局，方便你两边对着读：

```text
ebpf-observability/
├── main.go                    # 现有单机版，保留当练习场
├── cmd/
│   └── agent/main.go          # DaemonSet 里跑的 agent
├── bpf/
│   ├── vmlinux.h
│   └── flow.bpf.c             # 逐步演进
├── pkg/
│   ├── watcher/endpoint/      # Layer 0: veth 发现 + diff + 广播
│   ├── plugin/packetparser/   # 挂载 + 读 ringbuf + 造 flow
│   ├── k8s/                   # Layer 2: informer（Pod/Namespace/owner）
│   ├── cache/                 # Layer 2: IP → workload 索引
│   ├── enricher/              # Layer 2: flow + 元数据 → 打印
│   ├── rules/                 # Phase 4: 兜底规则（CIDR/端口 → 标签）
│   └── filter/                # Phase 4 可选: LPM_TRIE 降载 + 引用计数
├── deploy/
│   ├── namespace.yaml           # namespace: ebpf-obs
│   ├── rbac.yaml                # SA + 读取 Pod/Namespace/owner 的权限
│   ├── configmap.yaml           # 兜底规则（Phase 4）
│   ├── daemonset-hostpath.yaml  # 开发期用这个（scp 二进制，秒级迭代）
│   ├── daemonset.yaml           # 镜像版（后期）
│   ├── Dockerfile
│   └── README.md                # 集群事实 + 部署步骤 + 坑
└── README.md
```

---

## Phase 0 — 地基：让 agent 在真实节点上跑起来

**目标**：一个空壳 agent，跑在集群节点上，能挂上一个最小 TC 程序。

### 任务

1. 装 `bpftool`、`kubectl`，接入 kubeconfig
2. 查清第 2 节那三个集群事实（内核版本 / BTF / 镜像分发）
3. 写 Dockerfile
4. 写 DaemonSet manifest
5. 把现有最小 TC 程序改造成 agent 的入口，在集群里验证挂载

### DaemonSet 的关键配置

```yaml
spec:
  hostNetwork: true        # 必须：才能看到宿主机的 netns 和 veth
  hostPID: true            # 建议：方便排查
  containers:
    - securityContext:
        privileged: true   # eBPF 需要 CAP_BPF + CAP_NET_ADMIN
      volumeMounts:
        - { name: bpf,   mountPath: /sys/fs/bpf }
        - { name: debug, mountPath: /sys/kernel/debug }
  volumes:
    - { name: bpf,   hostPath: { path: /sys/fs/bpf } }
    - { name: debug, hostPath: { path: /sys/kernel/debug } }
```

> **`hostNetwork: true` 是这一层的地基。** 没有它，agent 只能看到自己 pod 的 netns，
> 看不到宿主机上其他 pod 的 veth，Layer 0 就无从谈起。
> retina 的 DaemonSet 同样如此（`deploy/` 下的 helm chart）。

### 验收标准

- [ ] `kubectl get ds -n <ns>` 显示所有节点 READY
- [ ] `kubectl logs ds/ebpf-obs-agent` 能看到 agent 打印出**宿主机**的网卡列表（不是容器里的）
- [ ] 在节点上 `bpftool prog list` 能看到你的程序
- [ ] 删掉 DaemonSet，程序自动卸载（bpf_link 引用计数归零）

### 坑

- **镜像分发**：远程集群拉不到本地镜像。要么推私有 registry，要么临时用 hostPath 挂二进制。这个不解决，后面每改一行代码都要折腾一次，**优先解决**。
- **内核版本不一致**：集群节点可能和你本机不同。TCX 需要 6.6+，低于此要写回退分支。
- **节点没有 BTF**：`/sys/kernel/btf/vmlinux` 不存在的话 CO-RE 失效，需要自己提供 BTF（这是另一个话题，遇到再说）。
- **`privileged: true` 是偷懒做法**。严格做法是只给 `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON`，可以之后收紧。

### 可移植性自检（preflight）

**这是"支持任意云厂商"的实现方式。** 代码本身不含云厂商假设，但环境差异客观存在——
所以把假设从"隐含在代码里"变成"启动时显式检查、检查不过就明确报错"。

一个观测工具在不适配的环境里**看起来在跑但数字是错的**，比直接崩溃危险得多。

启动时逐项检查并打日志：

| 检查项 | 怎么查 | 不满足时的后果 |
|---|---|---|
| 内核版本 / TCX 支持 | `features.HaveProgramType(ebpf.SchedCLS)` 试探性挂载 | < 6.6 → 必须走 clsact 回退（retina 的 `attachViaTC`） |
| BTF | `features.HaveBTF()` | CO-RE 失效，得自带 BTF |
| map 类型支持 | `features.HaveMapType(ebpf.LPMTrie)` | Phase 4 的可选降载用不了（主线不受影响） |
| **CNI 是否用 veth** | dump link，数 `Type()=="veth"` 的个数 | **0 个 → ipvlan/macvlan 类 CNI，Layer 0 整个失效** |
| 网卡堆叠深度 | 沿 `MasterIndex` / sysfs `lower_*` 递归向上 | 多层堆叠（bond → VLAN 等）时，"跳一层"不够 |
| 默认路由出接口 | 连外网看内核选了谁，或读 `/proc/net/route` | 找不到 → 节点口未知 |
| 权限 | 试加载一个最小程序 | 缺 `CAP_BPF` / `CAP_NET_ADMIN` |
| `RLIMIT_MEMLOCK` | 读 rlimit | 老内核上 map 加载失败 |

**用现成的库，别手搓**：`github.com/cilium/ebpf/features` 就是干这个的
（`HaveProgramType` / `HaveMapType` / `HaveBTF` / `HaveProgramHelper`）。

期望的输出形态：

```text
✓ 内核 6.8.0-31，TCX 可用
✓ BTF /sys/kernel/btf/vmlinux 存在
✓ 发现 veth 10 个 → CNI 是 veth 模式
⚠ 检测到 2 个 slave（eth1/eth2 master=eth0），将跳过
✓ 节点口 = eth0（默认路由出接口）
```

**换一个云，第一屏日志就告诉你哪里不满足**——这就是可移植性。

### 各环境的差异矩阵（供参考）

| 环境 | 节点网卡形态 | veth |
|---|---|---|
| 本集群（UCloud） | net_failover：virtio master + virtio standby + mlx5 VF | ✅ |
| Azure AKS | 同构（virtio + 加速网卡 primary）——逻辑可复用 | ✅ |
| AWS EKS | 单/多 ENI，通常无堆叠 | ✅ |
| GKE | eth0 单口 | ✅ |
| 自建 / on-prem | bond、team、VLAN、OVS，什么都可能有 | ✅ |
| Cilium **ipvlan** 模式 / macvlan 类 CNI | 无 veth | ❌ |

**最大的硬依赖是 veth 假设**——覆盖绝大多数 CNI，但不是全部。

---

## Phase 1 — Layer 0：接口绑定

**目标**：自动发现本节点所有 Pod 的 veth，挂上 tc 程序；Pod 创建/删除时自动挂载/清理。

> **分步教程见 [docs/phase1.md](docs/phase1.md)** —— 每一步的目标、要调的 API、自检问题、验收标准。
> 本节讲原理，那篇讲怎么做。

这一层**完全不碰 k8s API**，纯 netlink。

### 核心机制

```text
每 30s 循环：
  dump 宿主机所有 link  →  筛出 type == "veth"
  ↓
  和上一轮的结果做 diff  →  得到 created[] / deleted[]
  ↓
  广播 EndpointCreated / EndpointDeleted 事件
  ↓
  订阅者：created → 建 qdisc 并挂程序；deleted → 卸载并清理
```

### 关键设计决策

**1. veth 的身份用什么表示？**

retina 用的是三元组（`pkg/watchers/endpoint/types.go:11-19`）：

```go
type key struct {
    name         string
    hardwareAddr string
    netNsID      int
}
```

注意这里**没有 Pod IP**——它是内核视角的接口身份，不是 k8s 视角的身份。

**实测数据（2026-10-15，worker 10.13.177.131，用 `ip -j -d link show` 读的原始 netlink）：**

| ifindex | ifname | kind | MAC | `NetNsID` | `ParentIndex` | `MasterIndex` |
|---|---|---|---|---|---|---|
| 1 | lo | loopback | 00:00… | – | – | – |
| 2 | **eth0** | ether | `52:54:00:ca:e1:18` | – | – | – |
| 3 | eth1 | ether | `52:54:00:ca:e1:18` | – | – | **2** |
| 4 | eth2 | ether | `52:54:00:ca:e1:18` | – | – | **2** |
| 5–16 | ucni*（10 个） | **veth** | 各不相同 | **0~9** | **3** | – |

三个结论：

1. **`NetNsID` 不是 `-1`**，是**对端（Pod）netns 的编号**，0~9 各不相同。
   但**它会被复用**——Pod 删了、netns 销毁，号会被下一个 Pod 拿走。
   所以它能区分「此刻的 veth」，**不能当持久身份**。
2. **三块网卡 MAC 完全相同**，所以 **MAC 不能做接口身份**。
   这让三元组里的 `name` 从"冗余"变成"必需"。
3. **所有 veth 的 `ParentIndex` 都是 3**——这就是 `ip link` 里
   `ucni015abd619c5@if3` 那个 `@if3` 的来源（对端在 Pod netns 里的 ifindex）。

**对应到 vishvananda/netlink 的字段**（Step 1 要打印的就是这些）：

| 上面的列 | Go 里的读法 |
|---|---|
| kind | `link.Type()` |
| MAC | `link.Attrs().HardwareAddr` |
| NetNsID | `link.Attrs().NetNsID` |
| ParentIndex | `link.Attrs().ParentIndex` |
| **MasterIndex** | **`link.Attrs().MasterIndex`** |

**由这些数据推出的接口选择规则**（不硬编码任何接口名）：

```text
遍历所有 link：
  kind == "veth"                      → Pod 口（10 个）→ 挂 Endpoint{Ingress,Egress}
  kind != "veth" && MasterIndex == 0  → 候选节点口     → 再确认它是默认路由出接口
  MasterIndex != 0                    → 跳过（eth1/eth2 是别的设备的 lower device）
```

第二条是关键。**`MasterIndex != 0` 一律跳过**——这条规则不依赖"这个集群长什么样"，
换成别的云厂商、别的堆叠方式（bond / bridge / team / net_failover）同样成立，
因为它们都用同一个 netlink 属性表达从属关系。

不这么做的后果：eth0 是 net_failover master，发包路径是
`dev_queue_xmit(eth0) → net_failover 转发 → dev_queue_xmit(eth2)`。
**如果 eth0 和 eth2 都挂了 tc，egress 方向同一份报文会被计两次。**

> 这条是基于内核路径的推断，**没有实测验证**。跑通 Phase 1 后值得做个对照实验：
> 只挂 eth0 记录一组计数，再挂上 eth2 对比。能自己设计这个实验比记住结论有价值。

**2. 为什么要 diff，而不是监听事件？**

netlink 的 rtnetlink multicast 可以监听 link 变化，但 veth 的创建/删除在容器场景下
事件量、可靠性、以及"漏事件后如何自愈"都是问题。**周期性全量 dump + diff 是自愈的**：
漏了一轮，下一轮自然补上。这是可观测性组件的常见取舍。

retina 的实现：`pkg/watchers/endpoint/endpoint.go:57-86` `Refresh()`，diff 逻辑在 `:89-104`。

**3. 挂哪个程序到哪块网卡？**

retina 的映射（`packetparser_linux.go:601-611`）：

| 接口类型 | ingress 程序 | egress 程序 |
|---|---|---|
| veth（Pod 侧） | `EndpointIngressFilter` | `EndpointEgressFilter` |
| 主机默认网卡 | `HostIngressFilter` | `HostEgressFilter` |

**这里有个关键洞察：包的方向不是从包里读出来的，而是由「挂在哪个程序上」隐含决定的。**
veth 上的包天然属于该 Pod，eth0 上的天然属于节点。所以事件结构体里只需要一个
`ObservationPoint` 字段，由程序自己填。

**4. 只观测，不裁决**

retina 的程序永远 `return TC_ACT_UNSPEC`（`packetparser.c:291,301,309,317`），
意思是「我不做转发决策，交给链上的下一个程序」。
用 TCX 挂载时还要 `Anchor: link.Head()` 插到链头，保证在 Cilium 这类策略程序
**丢包之前**看到包（`packetparser_linux.go:613-623`）。

如果你的集群装了 Cilium/Calico，**这一步不做，你会看不到被策略丢弃的包**。

**5. 挂载要幂等**

同一个 veth 可能被重复通知。retina 用 `attachmentMap` + 每接口一把锁
（`packetparser_linux.go:552-556`）保证不会重复挂。

### 验收标准

- [ ] `kubectl run test --image=nginx` 后，一个周期内 agent 日志出现 `endpoint created`
- [ ] 新 Pod 的 veth 上确实挂上了程序（节点上 `bpftool net show dev <veth>`）
- [ ] `kubectl delete pod test` 后出现 `endpoint deleted`，且程序被清理
- [ ] agent 重启后能重新发现所有已有 veth（自愈）

### 坑

- **宿主机默认网卡怎么找**：不是写死 `eth0`。retina 用 `utils.GetDefaultOutgoingLinks()`
  （`packetparser_linux.go:369-384`）。做法是建个 socket 连一下外网，问内核选了哪个接口。
  这个集群碰巧就叫 eth0，换成别的云厂商就不是了，**硬编码是巧合不是正确**。
- **多网卡**：见上面「接口选择规则」。本集群有 net_failover，**不能遍历所有 link 都挂**。
  retina 目前也只取第一块（`packetparser_linux.go:376` 有注释
  `// Take first link until multi-link support is implemented`）。
- **lo 要不要挂**：Pod 内部的 loopback 通信在宿主机看不到，先不挂。
- **清理时机**：Pod 删除时 veth 可能已经消失，清理要容忍 `LinkNotFound`。

---

## Phase 2 — 全量事件流：ringbuf

**目标**：把节点上所有 TCP 连接的结构化事件实时送到终端。本阶段**不碰 k8s、不做过滤**。

为什么先做这个：Layer 2 的全部输入就是它。没有"一条 flow 从哪来、到哪去、方向是什么"，就无从归类。先把数据完整地捞出来，再讨论"它是谁的"。

> 「全量」指的是**所有 flow**，不是所有包。逐包上报在高流量下会淹掉用户态，而归类只需要"每条连接一条记录"。什么时候发事件，是本阶段最重要的设计决策。

### 和现在的差别

| | Phase 1 结束时 | Phase 2 |
|---|---|---|
| 数据在哪 | 内核 map（flows / toa_map） | 结构化事件推送到用户态 |
| 用户态怎么拿 | 每秒轮询一次快照 | 实时读 ringbuf |
| 覆盖范围 | 有 | 有（含同节点 Pod 互访） |
| 是否过滤 | 否 | 否 |

### 两种机制的取舍

| | PERF_EVENT_ARRAY | RINGBUF |
|---|---|---|
| 内核要求 | 老内核也行 | 5.8+ |
| 结构 | **每 CPU 一个缓冲区** | 所有 CPU 共享一个环形缓冲 |
| 读取 | 单线程轮询所有 CPU 的 buffer | 单线程读共享环 |
| 高核数表现 | 核数多了上下文切换开销上升 | 更好 |
| 顺序 | 不保证 | **保证** |

retina 默认用 perf array，但支持 `packetParserRingBuffer=enabled` 切到 ringbuf。
他们的文档里专门记录了一个用户在高核数节点上遇到的性能问题
（`docs/03-Metrics/plugins/Linux/packetparser.md`）——很值得读，是真实世界的取舍。

本项目直接用 ringbuf。

### 事件结构体设计

参考 retina 的 `packetparserPacket`（生成的 Go 结构在
`pkg/plugin/packetparser/packetparser_bpfel_x86.go:71-111`），字段分四组：

```text
身份：     五元组（src/dst ip, src/dst port, proto）
方向：     ObservationPoint   ← 由挂载点决定，不是从包里读的
TCP 细节： flags / seq / ack / tsval / tsecr（按需）
观测结果： 包长、累计包数/字节数、TOA 真实客户端
```

**方向是 Phase 1 留下的坑，这里必须修。** 现在 `handle(skb, egress)` 用一个 bool 表示方向，
它在 eth0 上对、在 veth 上是反的。改成由挂载点传入枚举：

| 挂载点 | ObservationPoint | 含义 |
|---|---|---|
| veth ingress | `FROM_ENDPOINT` | Pod 在发包 |
| veth egress | `TO_ENDPOINT` | 包发给 Pod |
| eth0 ingress | `FROM_NETWORK` | 从网络进来 |
| eth0 egress | `TO_NETWORK` | 发往网络 |

### 什么时候发事件

这是本阶段真正的设计工作。逐包上报不可行，retina 的取舍是：

- **map 里维护每条连接的累计计数**（原子累加）
- **ringbuf 只在有意义的时刻发**：
  - 新连接（SYN）
  - 连接关闭（FIN/RST）
  - 周期性上报（距上次超过 `reportInterval`）
  - 连接被 LRU 淘汰

你要自己定一个策略并写清楚理由。验收时会用 `iperf` 对比事件速率。

### 验收标准

- [ ] 终端能实时看到流事件，而不是每秒一次的快照
- [ ] 同节点 Pod 之间互访也能看到
- [ ] 方向字段正确（veth ingress 的事件里，saddr 是 Pod）
- [ ] 用 `iperf` / `curl` 打流量，事件速率在预期内
- [ ] ringbuf 满了有丢事件计数，不是静默丢失

### 坑

- **`bpf_ringbuf_reserve` 之后必须 `submit` 或 `discard`**，漏掉任何一个都会泄漏。
  verifier 对这条路径检查很严，分支要写清楚。
- **结构体 padding**：你在 `toa_client` 里已经踩过一次。ringbuf 传的是裸内存，
  Go 按结构体解析，两边对齐必须严格一致。**在 C 里显式写 `pad` 字段。**
- **`bpf_loop` 里能不能用 ringbuf**：TOA 解析用了 `bpf_loop`，注意 helper 在回调里的限制。
- **字节序**：约定「IP 存网络字节序，端口在 C 里用 `bpf_ntohs` 转成主机序」，
  两边注释清楚。现有 `flow_key` 就是这个约定，保持。
- **事件大小与频率**：ringbuf 的容量按"最坏情况下每秒事件数 × 单条大小 × 缓冲秒数"估，
  不是拍脑袋。

---

## Phase 3 — Layer 2：语义绑定（核心）

**目标**：把 `10.1.2.3:443 ↔ 10.1.2.4:52100` 变成
`default/nginx (Deployment/app) ↔ kube-system/coredns (Deployment/coredns)`。
**归类不了也要输出**，标成 `unknown`，保留五元组。

### 核心机制

```text
informer watch 本节点 Pod + Namespace + owner 对象
    ↓
索引：ip → workloadKey → {namespace, pod, workload kind/name, labels}
    ↓
事件到达 → 异步入队 → 查 src/dst → 填元数据 → 打印
```

### 关键设计决策

**1. 只 watch 本节点，且排除 hostNetwork**

retina 在服务端做的过滤（`cmd/standard/daemon.go:193-212`）：

```text
spec.nodeName == $NODE_NAME  AND  status.podIP != $NODE_IP
```

第二个条件是个 workaround：**k8s 不支持 `spec.hostNetwork` 这个 field selector**，
而 hostNetwork 的 Pod 和节点共享 IP，会污染 IP → Pod 映射。retina 用「Pod IP 不等于节点 IP」排除。

我们自己实现时，`spec.nodeName` 仍然走服务端 field selector；hostNetwork 在本地用
`pod.Spec.HostNetwork` 判断，语义更直接。另外可以把**节点 IP 映射成节点自身**
（`node/<nodeName>`），这样 eth0 上的流量不会变成 unknown。

**2. 索引结构**

retina 用普通 `map` + `sync.RWMutex`，不是 k8s 的 `cache.Indexer`
（`pkg/controllers/cache/cache.go:17-45`）：

```text
ipToEpKey[ip] → "namespace/name"     ← 一级：IP 找 key
epMap[key]    → *Workload            ← 二级：key 找对象
```

两级而不是一级，是为了让「同一个对象换 IP」时只改索引、不动对象。
对我们来说还多一层：key 要能表达"Pod 属于哪个 Deployment/StatefulSet"。

**3. owner 链：Pod → ReplicaSet → Deployment**

`pod.OwnerReferences` 只指向**直接** owner：

| Pod 的 owner | 需要再查一层 | 最终 workload |
|---|---|---|
| ReplicaSet | 是，查 RS 的 owner | Deployment |
| StatefulSet | 否 | StatefulSet |
| DaemonSet | 否 | DaemonSet |
| Job | 可选，查 Job 的 owner | CronJob |
| 无 | 否 | 裸 Pod |

所以要 watch `apps/v1` 的 ReplicaSets（至少）。两个原则：

- **owner 缺失不能丢数据**：RS 已被删、ownerReferences 为空、UID 对不上，
  都退化成 Pod 级归类，而不是输出 unknown。
- **按 UID 而不是名字匹配 owner**：同名对象被删除重建后 UID 会变，
  用名字匹配会把新 Pod 归到旧 Deployment 上。

**4. 富化必须在旁路，不能阻塞采集**

retina 的做法（`pkg/plugin/packetparser/packetparser_linux.go:899-918`）：
采集线程只做 `enricher.Write(ev)` 入队就返回，真正的查表在另一个 goroutine。

> 这里的 ring 是**用户态内存队列**（cilium 的 `container.Ring`），
> **不是** Phase 2 的 BPF ringbuf。两者同名但不同层。

队列满了怎么办？retina 的选择是**丢弃 + 计数**，绝不拖慢采集线程。
这个取舍要写进你的实现里，并暴露一个 counter。

**5. 不需要 LRU/TTL**

retina 的 enricher 没有 LRU、没有 TTL：它查的是 controller 主动维护的本地 map，
不是每次去问 apiserver。代价是元数据可能短暂过期（Pod 刚删、map 还没更新），
换来的是每个事件只做一次内存查表。

**6. 未知 IP 是一等公民**

查不到不等于没价值。输出格式里必须能表达：

```text
10.13.189.121:443 → 10.13.177.131:52100   unknown ↔ node/10.13.177.131
```

Phase 4 的兜底规则就是在这一步接入：k8s 查不到 → 查用户规则 → 仍然查不到 → unknown。

### 验收标准

- [ ] 终端输出从 IP 变成 `namespace/pod`，并带上 Deployment/StatefulSet 名
- [ ] 新建一个 Pod 并访问它，输出里是正确名字
- [ ] hostNetwork 的 Pod **不会**出现在 IP 索引里
- [ ] owner（RS）被删除后，类似流量退化成 Pod 级，而不是 unknown
- [ ] 完全未知的 IP 仍然打印，并标 `unknown`
- [ ] 高流量下富化不拖慢采集（对比 Phase 2 的事件速率）

### 坑

- **informer 的启动同步**：`WaitForCacheSync` 之前不要开始富化，否则前面的事件全是 unknown。
- **IP 复用**：写入索引前先按 IP 删旧对象（retina 的 `cache.go:226-238` 就是这么做的）；
  删除事件到达时要检查这个 IP 是否已被新 Pod 占用。
- **ownerReferences 的 UID 校验**：只认 UID，不认名字。
- **RBAC**：需要 `pods`、`namespaces`、`replicasets`、`statefulsets`、`daemonsets`
  的 `get/list/watch`。ClusterRole 里一次配齐。
- **IPv6 / 双栈**：可以先不做，但结构体留好位置
  （retina 用 `IPAddresses{IPv4, IPv6, OtherIPv4s, OtherIPv6s}`）。
  注意 retina 的 `packetparser` 本身是 IPv4-only 的。
- **事件与索引的时序**：事件可能比索引更新更早到达，未知结果允许短暂出现，
  不要在未知时做负缓存（否则 Pod 新建后要等很久才认得出来）。

---

## Phase 4 — 兜底规则与可选的降载

**目标**：让「k8s 归类不了」的流量也有归属；流量太大时，再考虑内核侧过滤。

### 4a 兜底规则（主线）

因为你不用 CRD，最简载体是一个 ConfigMap：

```yaml
# deploy/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ebpf-obs-config
  namespace: ebpf-obs
data:
  config.yaml: |
    fallback:
      - name: nlb
        cidr: 10.0.0.0/8
        label: external/nlb
      - name: mysql
        port: 3306
        label: service/mysql
```

**匹配顺序是固定的**：

```text
1. k8s 索引命中（Pod / Deployment / StatefulSet / 节点）
       → 用 k8s 的身份，结束
2. k8s 未命中 → 按规则列表匹配
       → CIDR 取最长前缀；端口精确匹配；同一优先级按 name 排序保证确定性
3. 仍未命中 → unknown，保留五元组
```

三个原则：

- **兜底规则永远不覆盖 k8s 结果**。它是"补充"，不是"改写"。
- **日志里必须输出命中的 rule name**，否则用户无法判断这条记录为什么被标成某个身份。
- **配置无效时保留上一版规则**，并大声报错。不要因为一次写错就退回全 unknown。

> 规则匹配的是"IP 或端口"，不是负载内容。要做 L7 识别（HTTP host、TLS SNI）是另一个话题，
> 不在本项目范围内。

### 4b 可选的 Layer 1：LPM_TRIE 降载

**只有当初期方案跑不动时才做**——事件量过大、CPU 或 ringbuf 丢包成为实际瓶颈。

机制和 retina 一致：

```text
用户态规则/选择器 → IP 白名单 → LPM_TRIE
内核：src 或 dst 命中才继续，否则 return TC_ACT_UNSPEC
```

要点：

- **过滤的是观测，不是流量**。`TC_ACT_UNSPEC` 让包继续走，只是不采集。
- **默认关闭**。过滤掉的数据无法补回，这是一个需要显式开启的取舍。
- **必须有"被过滤掉的包数"计数**，否则你无法判断降载是否误伤。
- 引用计数、LPM key 字节序、批量更新这些坑见 retina 的
  `pkg/managers/filtermanager/cache.go` 与 `pkg/plugin/filter/filter_map_linux.go`。

### 验收标准

- [ ] unknown 的 IP 能被兜底规则标成预期名字
- [ ] 规则修改后热生效，不需要重启 agent
- [ ] k8s 能归类的流量**不会**被兜底规则覆盖
- [ ] （可选）打开过滤后事件速率下降，且"被过滤包数"计数正确
- [ ] 配置写错时报错清晰，且维持上一版规则

### 坑

- **LPM key 的字节序**：`{prefixlen, data}`，`data` 是网络序原样；写错不会报错，只是永远不命中。
- **批量更新**：`BatchUpdate` 不是所有内核都支持，要能退化成单条 `Put`
  （retina 的 `pkg/plugin/filter/filter_map_linux.go:81-118`）。
- **过滤规则的删除**：lookup 是最长前缀匹配，但 delete/update 要求 key 完全相等，
  前缀长度是 key 的一部分，删除时不能用 `/32` 去删一条 `/8`。
- **默认关闭**：不要为了"看起来性能好"而默认过滤，那会让数据静默变少。

---

## 6. 从 retina 抄什么 / 不抄什么

### 抄

| 机制 | retina 位置 | 为什么值得抄 |
|---|---|---|
| veth 三元组身份 + 周期 diff | `pkg/watchers/endpoint/` | 自愈，不依赖事件可靠性 |
| 方向由挂载点决定 | `packetparser_linux.go:601-611` | 比在包里判断方向干净得多 |
| TCX `Anchor: Head()` | `packetparser_linux.go:613-623` | 不看这个会漏掉被策略丢的包 |
| 服务端 field selector 过滤 | `cmd/standard/daemon.go:193-212` | 大集群里的关键优化 + hostNetwork workaround |
| owner 链解析 | `pkg/controllers/cache/` | Pod → RS → Deployment，输出到 workload 而不是只到 Pod |
| 明细走 ringbuf / 聚合走 map | `packetparser.c` + conntrack | 事件量的根本取舍 |
| 异步富化 + 满了丢弃 | `packetparser_linux.go:899-918` | 采集热路径绝不能被富化阻塞 |
| 引用计数 filtermanager | `pkg/managers/filtermanager/cache.go` | **Phase 4 可选降载**时，IP 被多规则共享的正确性 |

### 不抄

| 机制 | 原因 |
|---|---|
| `RetinaEndpoint` CRD | 你不需要；那是为「大集群里每个 DaemonSet 都 watch 全量 Pod 会打爆 apiserver」设计的 |
| Operator / DaemonSet 角色分离 | 同上，是规模问题，不是机制问题 |
| Cilium ipcache 那条富化路径 | retina 有**两套**平行的 IP→workload 实现（`pkg/enricher` 和 `pkg/hubble`）。你只需要一套 |
| Prometheus exporter | 你说了不要，终端输出即可 |
| `SharedInformerFactory` | retina 里那个是**空转的**（建了 factory 但没注册任何 informer）。真正的采集走 controller-runtime manager。别照抄这个 |

---

## 7. 进度追踪

### 主线阶段

- [x] **Phase 0** 地基：agent 在真实节点跑起来，最小 TC 程序挂载成功
      （3/3 READY，hostNetwork 生效，宿主网卡可见）
- [x] **Phase 1** Layer 0：veth 自动发现 + TCX 挂载/清理
      （分步教程见 [docs/phase1.md](docs/phase1.md)）
- [ ] **Phase 2** 全量事件流：ringbuf 实时事件（不筛选、不碰 k8s）
- [ ] **Phase 3** Layer 2：informer + owner 链 + IP 索引 + enricher，输出 workload 身份
- [ ] **Phase 4** 兜底规则（ConfigMap）+ 可选的 LPM_TRIE 降载

> **2026-10-25 设计调整**：原计划把 Layer 1（LPM_TRIE 过滤）放在 Phase 2，
> 先筛选再采集。后来改为**先全量采集、用户态归类**：
> 筛选要求事先知道关心谁，而归类不需要；被过滤掉的流量无法补回。
> 已完成的过滤原型已回滚（`git stash`），LPM_TRIE 降级为 Phase 4 的可选项。

### 可移植性（preflight）

见本文件 Phase 0 末尾的「可移植性自检」。这些是"支持任意云厂商"的落地项：

- [ ] 内核 / TCX 支持检测（`features.HaveProgramType`）
- [ ] BTF 检测（`features.HaveBTF`）
- [ ] map 类型检测（`features.HaveMapType(ebpf.LPMTrie)`）
- [ ] **CNI 是否用 veth** 检测（veth 数为 0 → 明确报错，别静默跑）
- [ ] 网卡堆叠深度检测（沿 `MasterIndex` 递归向上，处理多层堆叠）
- [ ] 默认路由出接口自动发现（**别硬编码 "eth0"**）
- [ ] 权限 / `RLIMIT_MEMLOCK` 检测
- [ ] **在第二个环境上验证**（kind / k3s / 另一家云），跑通即证明可移植性

### 独立小目标（穿插做，不阻塞主线）

- [ ] TOA 收尾：FIN/RST 清理、NLB 网段校验
- [ ] tracepoint 入门：自己写一个 execsnoop
- [ ] `bpftool net show` / `map dump` / `prog list` 熟练使用

---

## 附：调试命令速查

```bash
# 看内核里加载了哪些程序
bpftool prog list

# 看某块网卡上挂了什么
bpftool net show dev <iface>

# dump map 内容（验证 flow 聚合 / Phase 4 的 LPM key 字节序）
bpftool map list
bpftool map dump name flows
bpftool map dump name flow_filter     # Phase 4 可选降载

# 看 bpf_printk 输出
cat /sys/kernel/debug/tracing/trace_pipe

# 看反汇编（确认编译器没优化掉你的检查）
llvm-objdump-18 -d -S bpf_bpfel.o

# 看 verifier 日志（加载失败时，cilium/ebpf 会打印）
# 提高日志等级：loadBpfObjects(&objs, &ebpf.CollectionOptions{
#     ProgramLogLevel: ebpf.LogLevelInstruction })
```

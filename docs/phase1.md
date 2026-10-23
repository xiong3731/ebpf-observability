# Phase 1 分步教程：Layer 0 接口绑定

目标：**自动发现本节点所有 Pod 的 veth，挂上 tc 程序；Pod 创建/删除时自动挂载/清理。**

设计原理见主 [README](../README.md) 的 Phase 1 一节。本文只讲**怎么做**。

> 代码留给你写。这里给的是每一步的目标、要调的 API、以及**自检问题**——
> 每一步都能独立验证，跑出结果再进入下一步。

---

## 前置

环境已经就绪：bpftool 三个节点都装了，`hack/dev.sh` 可用，`vishvananda/netlink` 已加进 go.mod。

先确认当前基线：

```bash
# 应该看到 3/3 READY，只有 eth0 上有程序
kubectl get ds -n ebpf-obs
ssh root@10.13.177.131 'bpftool net show'
```

---

## Step 1.1 — 先只观察，不写任何逻辑

**目标**：搞清楚 netlink 到底给你什么。这一步**不做筛选、不做挂载**。

新建一个文件（建议 `cmd/agent/main.go`），做一件事：

1. `netlink.LinkList()` 拿到所有 link
2. 遍历，每个打印一行：`ifindex / name / Type() / MAC / NetNsID / ParentIndex / MasterIndex`
3. 打印完 **阻塞等信号**（不要退出，否则 DaemonSet 会一直重启）

用 `%v` 打印 `HardwareAddr`，用 `%d` 打印那几个 index，注意 `NetNsID` 是 `int`。

**跑起来**：

```bash
hack/dev.sh ./cmd/agent
```

**自检**——对照节点上的原始 netlink 数据：

```bash
ssh root@10.13.177.131 "ip -j -d link show | jq -r '.[] | [.ifindex,.ifname,.link_type,.address,(.link_netnsid // \"-\"),(.link_index // \"-\"),(.master // \"-\")] | @tsv'"
```

两边应该**逐字段对得上**。对不上就说明字段读错了（最常见是 `MasterIndex` 和 `ParentIndex` 搞反）。

> **为什么先做这一步**：netlink 返回的字段比想象中多，也有几个容易搞混的
> （`ParentIndex` vs `MasterIndex`、`NetNsID` 的真实含义）。
> 先看清楚再写逻辑，后面调试省一半时间。

---

## Step 1.2 — 接口分类

**目标**：把 link 分成三类，先只打印分类结果，**还是不要挂载**。

按主 README 里那条规则：

```text
kind == "veth"                      → Pod 口
kind != "veth" && MasterIndex == 0  → 候选节点口
MasterIndex != 0                    → 跳过
```

**自检问题**（用你的输出回答，别猜）：

1. 分出来的 Pod 口有几个？和 `ip -o link show type veth | wc -l` 对得上吗？
2. 候选节点口有几个？如果不止一个，你怎么从里面挑出真正承载流量的那个？
   （提示：读 `/proc/net/route` 找 default 路由，或者建个 socket 连 8.8.8.8 看内核选了谁）
3. eth1/eth2 被正确跳过了吗？

第 2 问是关键——**别硬编码 "eth0"**。这个集群碰巧叫 eth0，换个云厂商就不是了。

---

## Step 2 — 挂载

**目标**：给 Step 1.2 分出来的接口挂上 TCX 程序。

- Pod 口：`link.AttachTCX`，ingress 挂 `objs.TcIngress`，egress 挂 `objs.TcEgress`
- 节点口：同一对程序（Phase 1 先共用，Phase 3 再按 `ObservationPoint` 区分）

**先想清楚方向语义再动手**（这是本阶段真正的设计工作）：

| 挂载点 | 包的方向 | 谁是 Pod |
|---|---|---|
| `ucni*` **ingress** | Pod → 外面 | **saddr 是 Pod**（这是 Pod 的 egress） |
| `ucni*` **egress** | 外面 → Pod | **daddr 是 Pod**（这是 Pod 的 ingress） |

你现在的 `handle(skb, egress)` 里 `egress=1` 时把 `saddr` 当 local——这在 eth0 上对，
**在 veth 上是反的**。retina 用 `ObservationPoint`（`FROM_ENDPOINT` / `TO_ENDPOINT` /
`FROM_NETWORK` / `TO_NETWORK`）表达这件事，**它不是从包里读的，是从"挂在哪个接口的哪个 hook"推出来的**。

**自检**：

```bash
ssh root@10.13.177.131 'bpftool net show'     # 应该看到 eth0 + 10 个 ucni*，每个 2 条
```

**验收**：`kubectl run test --image=nginx` 之后，新 veth 上出现程序；
且日志里能看到**同节点 Pod 之间**的流量（这在 Phase 0 是看不到的）。

---

## Step 3 — 周期 diff + 清理

**目标**：Pod 会不停生灭，veth 跟着变。做成循环。

```text
每 30s：
  dump → 和上一轮做 diff → created[] / deleted[]
  created → 挂载
  deleted → 卸载 + 清理本地状态
```

**要处理好的三件事**：

1. **挂载幂等**：同一个接口可能被重复通知。retina 用 `attachmentMap` + 每接口一把锁
   （`packetparser_linux.go:552-556`）。你至少要有个 map 记录"这个接口挂过了"。
2. **清理要容忍接口已消失**：Pod 删除时 veth 可能已经没了，`LinkNotFound` 要当正常情况。
3. **为什么用周期 dump 而不是监听 netlink 事件**——想清楚这个问题。
   提示：如果某一轮因为任何原因漏了，下一轮会怎样？

**验收**：删掉一个 Pod，日志出现 `endpoint deleted`，且程序被卸载
（`bpftool net show` 里消失）；重建 Pod 能重新挂上。

---

## 卡住了看哪里

| 现象 | 先查什么 |
|---|---|
| 程序加载失败 | cilium/ebpf 会打印 verifier 日志，提高 `ProgramLogLevel` |
| 挂载返回 `operation not supported` | 内核 < 6.6，得改用 clsact + tc filter（retina 的 `attachViaTC`） |
| `bpftool net show` 里没有你的程序 | 进程退出了（bpf_link 引用计数归零自动卸载） |
| 只有 eth0 有流量，veth 没有 | 挂到宿主机侧 veth 了吗？确认 `NetNsID` 那一列不是空的 |

---

## 不想每次都重启 DaemonSet？

Step 1 是纯观察、不挂载，可以构建分发后，直接在 pod 里跑第二个实例：

```bash
# 构建 + scp，但不重启 DaemonSet
NO_RESTART=1 hack/dev.sh ./cmd/agent

# 在 pod 里手动跑新二进制，输出直接打在终端上
kubectl exec -it -n ebpf-obs ds/ebpf-obs-agent -- /opt/ebpf-obs/agent
```

这样改一行、跑一次只要几秒，也不用翻 DaemonSet 的滚动日志。

> **Step 2 之后不能用这招**——第二个实例会重复挂载 tc 程序。
> 到那时就老老实实 `hack/dev.sh` 走重启。

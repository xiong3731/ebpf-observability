# ebpf-observability

Go + eBPF 学习笔记与练习项目。用户态使用 [cilium/ebpf](https://github.com/cilium/ebpf)，内核态用 C 编写。

## 快速开始

```bash
# 1. 从当前内核导出类型定义（只需做一次）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# 2. 编译 BPF C 代码并生成 Go 绑定（每次改完 .c 都要重新执行）
go generate

# 3. 运行（需要 root）
go run .

# 4. 另开终端查看 bpf_printk 输出
cat /sys/kernel/debug/tracing/trace_pipe
```

---

## 1. 整体流程

```text
bpf/hello.bpf.c
     │  go generate → bpf2go → clang
     ▼
hello_bpfel.o ──(go:embed)──> _HelloBytes
                                   │ loadHelloObjects(&objs)
                                   ▼
                          内核（verifier 检查通过后加载）
                                   │ link.AttachTCX(...)
                                   ▼
                     挂到网卡 tc ingress，每个包触发一次
```

内核不认识 C 源码，只认 **BPF 字节码**，所以需要两步：

1. clang 把 `.c` 编译成 BPF 字节码（`.o`，ELF 格式）
2. Go 程序读取 `.o`，交给内核加载

**bpf2go** 把这两步都包了：替你调用 clang，并生成 Go 胶水代码。

## 2. go:generate 与 bpf2go

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel hello bpf/hello.bpf.c
```

- `//go:generate` **只是一条记在代码里的命令**。执行 `go generate` 时，Go 会把它当成 shell 命令执行。
  - `//` 和 `go:generate` 之间**不能有空格**
  - `go build` / `go run` **不会**自动执行它，改完 `.c` 必须先 `go generate`

### 参数

| 参数 | 含义 |
|---|---|
| `-target bpfel` | 小端字节码（x86、ARM64 都是小端）。也决定了文件名后缀 `_bpfel`。可选 `bpfeb`（大端）、`bpf`（两种都生成） |
| `hello` | 生成代码的**名字前缀**：`helloObjects`、`loadHelloObjects()`、`hello_bpfel.go`。与 C 函数名无关 |
| `bpf/hello.bpf.c` | C 源文件，路径相对于 `//go:generate` 所在文件的目录 |
| `-- -O2 -g -Wall` | `--` 之后的参数原样传给 clang（bpf2go 默认已带 `-O2 -g`） |

### 生成的文件（不要手改）

**`hello_bpfel.o`**：BPF 字节码，ELF 格式。

| section | 来自 |
|---|---|
| `tc` | `SEC("tc")` 修饰的函数指令 |
| `license` | `SEC("license")` |
| `.rodata` | 只读数据，比如 `bpf_printk` 的字符串 |
| `.BTF` / `.BTF.ext` | 类型信息和行号（`-g` 生成），verifier 报错时显示 C 源码行 |

查看反汇编：`llvm-objdump-18 -d -S hello_bpfel.o`

```text
r1 = 0x0 ll   ← 参数1：字符串地址（加载时重定位）
r2 = 0xe      ← 参数2：字符串长度
call 0x6      ← 6 号 helper：bpf_trace_printk
r0 = 0x0      ← r0 存返回值
exit
```

BPF 虚拟机有 r0 到 r10 共 11 个寄存器：r1 到 r5 传参，r0 放返回值。

**`hello_bpfel.go`**：Go 绑定。

| 内容 | 作用 |
|---|---|
| `//go:embed hello_bpfel.o` | 编译时把 `.o` 嵌入二进制，部署时不需要带 `.o` 文件 |
| `loadHelloObjects(obj, opts)` | 解析 ELF → 加载进内核 → 把结果填进结构体 |
| `helloObjects` | 嵌入了 `helloPrograms` / `helloMaps` / `helloVariables`，所以可以直接写 `objs.Hello` |
| `Hello *ebpf.Program \`ebpf:"hello"\`` | 结构体标签告诉库：这个字段对应 ELF 里名为 `hello` 的程序 |
| `helloSpecs` vs `helloObjects` | Specs 是**加载前**的描述；Objects 是**已加载**的内核对象（持有 fd） |
| `Close()` | 关闭 fd，释放内核对象 |
| `//go:build amd64 \|\| arm64 ...` | 只在小端架构上编译，和 `-target bpfel` 对应 |

## 3. BPF C 程序基础

```c
#include "vmlinux.h"            // 内核所有类型定义（struct __sk_buff 等）
#include <bpf/bpf_helpers.h>    // SEC()、bpf_printk() 等

#define TC_ACT_OK 0             // vmlinux.h 只有类型没有宏，要自己定义

SEC("tc")
int hello(struct __sk_buff *skb)
{
    bpf_printk("Hello, eBPF!");
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
```

| 元素 | 说明 |
|---|---|
| `vmlinux.h` | 由 bpftool 从内核 BTF 导出。本机没有 `/usr/include/asm`，用 `<linux/bpf.h>` 会编译失败，所以用 vmlinux.h |
| `SEC("tc")` | 把函数放进名为 `tc` 的 ELF section，**加载器据此判断程序类型** |
| `struct __sk_buff *skb` | 当前包的视图，有 `skb->len`、`skb->protocol` 等字段 |
| `bpf_printk` | 调试用的 printf，输出到 `trace_pipe`。速度慢、全局共享，正式代码别用。会自动换行 |
| 返回值 | `TC_ACT_OK`(0) 放行，`TC_ACT_SHOT`(2) 丢弃 |
| `license` | 很多 helper（包括 `bpf_printk`）只允许 GPL 兼容的程序调用 |

**踩坑**：`SEC('tc')` ❌ → `SEC("tc")` ✅。C 里单引号是字符，双引号才是字符串。

### SEC 名称是约定好的，不能随便写

对照表在 cilium/ebpf 源码 `elf_sections.go`（派生自 libbpf）。tc 相关：

| 写法 | 程序类型 | 挂载方向 |
|---|---|---|
| `SEC("tc")` | SCHED_CLS | 未指定，由 Go 里的 `Attach` 决定（最通用） |
| `SEC("tcx/ingress")` / `SEC("tc/ingress")` | SCHED_CLS | ingress |
| `SEC("tcx/egress")` / `SEC("tc/egress")` | SCHED_CLS | egress |
| `SEC("classifier")` | SCHED_CLS | 老写法，等同于 `tc` |

程序类型决定了：函数参数是什么、能调用哪些 helper、能挂到哪里。写成表里没有的名字，加载会失败。表里带 `+` 的（如 `kprobe+`）表示后面还要接具体目标，如 `kprobe/tcp_connect`。

## 4. 加载 vs 挂载，以及生命周期

```text
加载 (load)    loadHelloObjects()  程序进入内核，但没接到任何挂载点 → 不会被触发
挂载 (attach)  link.AttachTCX()    接到网卡 tc ingress 上 → 每来一个包执行一次
```

```go
l, err := link.AttachTCX(link.TCXOptions{
    Interface: iface.Index,          // 网卡 index，不是名字
    Program:   objs.Hello,
    Attach:    ebpf.AttachTCXIngress, // 或 AttachTCXEgress
})
defer l.Close()
```

- **TCX** 是内核 6.6+ 的新式 tc 挂载方式，不需要 `tc` 命令，也不需要 clsact qdisc
- 内核用**引用计数**管理 BPF 对象。用户态持有的 fd 就是引用
- **进程退出 → fd 自动关闭 → 引用归零 → 程序被卸载、释放**。这是 bpf_link 故意的设计：进程崩溃不会在网卡上留下"孤儿程序"
- 退出后仍然保留的两种情况：
  - **pin 到 bpffs**（`/sys/fs/bpf/xxx`），删掉文件才会卸载
  - 老式 `tc filter add`（netlink 挂载），要 `tc filter del` 手动删除

验证命令：

```bash
bpftool prog list | grep -A2 hello    # 内核里有没有这个程序
bpftool net show dev eth0             # 网卡上挂了什么
```

## 5. 用户态骨架（5 步，要记住）

```text
1. 找到挂载目标     net.InterfaceByName("eth0") → iface.Index
2. 加载程序         loadXxxObjects(&objs, nil)  → defer objs.Close()
3. 挂载程序         link.AttachXxx(...)          → defer l.Close()
4. 保持运行         等 Ctrl+C
5. 读取数据         从 map 里读（后续步骤）
```

具体 API 不用背：VS Code 里 **Ctrl+点击**跳转源码，或者查 [pkg.go.dev/github.com/cilium/ebpf](https://pkg.go.dev/github.com/cilium/ebpf)，参考 cilium/ebpf 仓库的 `examples/`。

## 6. 用到的 Go 知识点

| 知识点 | 例子 / 说明 |
|---|---|
| 错误处理 | `if err := f(); err != nil { ... }`，`err` 的作用域只在 if 内 |
| 错误包装 | `fmt.Errorf("加载: %w", err)`；用 `errors.As` 判断具体类型 |
| 传指针 | `loadHelloObjects(&objs, nil)`：函数要往结构体里填数据，传值只会填到拷贝上 |
| 零值 | `var objs helloObjects` 声明后字段都是零值（指针为 nil） |
| defer | 函数返回时执行，**后进先出**。先注册的 `objs.Close()` 最后执行 |
| `log.Fatal` 陷阱 | 会直接 `os.Exit`，**跳过 defer**。惯用法是逻辑放进 `run() error`，main 只负责退出 |
| 结构体字面量 | `link.TCXOptions{Interface: ..., Program: ...}`，未写的字段取零值 |
| 结构体嵌入 | 字段提升，`objs.helloPrograms.Hello` 可以简写成 `objs.Hello` |
| 结构体标签 | `` `ebpf:"hello"` ``，库通过反射读取 |
| channel + 信号 | `sig := make(chan os.Signal, 1)`；`signal.Notify(sig, os.Interrupt)`；`<-sig` 阻塞到按下 Ctrl+C |
| `go:embed` | 编译时把文件内容嵌入成 `[]byte` |
| 小写开头 | 包内私有（bpf2go 生成的 `helloObjects` 只给 main 包用） |

## 7. 程序类型怎么选

### 挂载位置

```text
                         ┌─────────────── 用户态 ───────────────┐
                         │   Nginx / App   malloc() free()       │  ← uprobe
                         └──────────────┬────────────────────────┘
  ═════════ 系统调用边界 ═════════════════│══════════════════════════
                                        │  ← tracepoint (syscalls/*)
                         ┌──────────────▼──── 内核 ─────────────┐
                         │  TCP/IP 协议栈  tcp_connect() ...      │  ← kprobe / fentry
                         │  socket 层                            │  ← socket filter / cgroup_skb
                         │  TC (ingress/egress)                  │  ← tc
                         │  网卡驱动                              │  ← xdp
                         └────────────────────┬──────────────────┘
                                         网卡收包
```

越靠近网卡：看到原始的包，速度快，但**不知道是哪个进程**。越靠近应用：有进程、参数等上下文，但离原始的包越远。

### 网络流量分析

| 程序类型 | 看到的是什么 | 最适合 |
|---|---|---|
| **tc** | 某块网卡上的每个包，**双向**。按网卡挂，lo/docker0/veth 要各自挂 | 按包解析、按五元组统计、**TOA 解析** |
| **xdp** | 某块网卡上的每个**收到**的包，驱动层、还没有 skb | DDoS 防护、四层负载均衡、高速黑名单 |
| **socket** | 挂在哪个 socket 就看哪个的包；挂 raw packet socket 可看整块网卡（tcpdump 原理）。只读，拷贝到用户态 | 抓包工具 |
| **cgroup_skb** | 某个 cgroup（容器）的包，双向 | **按容器**统计流量 |
| **kprobe / fentry** | **函数调用和参数**，带进程上下文（如 `tcp_sendmsg`） | **按进程**统计流量（tcptop 原理）、追踪建连和丢包原因 |

- tc 和 xdp **都要自己解析包头**。区别是：xdp 更快，但只能看收包，元数据也更少
- tc / xdp 知道**包内容**，不知道**进程**；kprobe 知道**进程**，但不适合逐包解析
- 实际项目常**组合使用**：tc 解析包和 TOA，kprobe/tracepoint 关联到进程或容器

### 追踪类怎么选

```text
有现成的 tracepoint ─────→ tracepoint（接口稳定，首选）
没有，内核 ≥ 5.5 ────────→ fentry / fexit（开销比 kprobe 小）
没有，老内核 ────────────→ kprobe / kretprobe（内核函数跨版本可能变）
```

查看可用的 tracepoint：`ls /sys/kernel/tracing/events/`

### CPU / 内存分析

**使用率多少**不需要 eBPF，读 `/proc`、cgroup 就行。eBPF 擅长回答 **"为什么"和"是谁"**。

| 分析目标 | 程序类型 | section 示例 |
|---|---|---|
| CPU 热点、火焰图、持续剖析（Parca/Pyroscope） | perf_event | `SEC("perf_event")` |
| off-CPU（在等锁/IO）、调度延迟 | tracepoint | `SEC("tracepoint/sched/sched_switch")`、`sched_wakeup` |
| 短命进程 | tracepoint | `SEC("tracepoint/sched/sched_process_exec")` |
| 用户态内存泄漏（memleak 原理） | uprobe | `SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:malloc")` |
| 内核内存分配 | tracepoint | `SEC("tracepoint/kmem/kmalloc")` |
| 缺页 | tracepoint | `SEC("tracepoint/exceptions/page_fault_user")` |
| 直接内存回收导致卡顿 | tracepoint | `SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")` |
| OOM | tracepoint | `SEC("tracepoint/oom/mark_victim")` |

- **perf_event**：定时采样（如 99Hz），记录调用栈，聚合后画火焰图。只能看到 on-CPU 时间
- **uprobe**：kprobe 的用户态版本。挂 `malloc`/`free`，map 里剩下没释放的就是疑似泄漏，不用改代码、不用重启。Go/Java 有 GC，用 pprof 更合适

现成工具（`apt install bpfcc-tools`，命令带 `-bpfcc` 后缀）：`profile`、`offcputime`、`runqlat`、`execsnoop`、`memleak`、`oomkill`、`tcptop`。先跑一跑建立直觉，源码也是好教材。

## 8. 项目目标背景：TOA

NLB 做 FullNAT 时，后端看到的源 IP 是 NLB 的 IP，真实客户端 IP 放在 TCP Option（TOA）里。

- `toa.ko` 解析 Option 后存进 socket，再 hook `inet_getname`，让 `accept()`/`getpeername()` 返回客户端 IP。**它不修改包头**
- 所以即使装了 `toa.ko`，tc/xdp 看到的 `src_ip` **仍然是 NLB IP**
- 方案：在 **tc ingress** 解析 TOA，建立 `NLB 四元组 → 客户端 IP:Port` 的 LRU_HASH 映射，后续的包按五元组查表
- 常见格式：Kind 200（UCloud）、254（兼容模式/部分 DPVS）、253，长度 8。**先抓包确认，不要硬编码**
- 注意事项：TOA 只出现在建连阶段；用 LRU 加超时；FIN/RST 时删除映射；只信任 NLB 网段；挂载点要在 NAT/CNI 改写五元组之前

## 学习路线

- [x] 最小 TC 程序：`bpf_printk` + 加载 + TCX 挂载
- [ ] 用 map 计数（包数 / 字节数），Go 每秒读一次
- [ ] 解析 Ethernet → IPv4 → TCP 头，按五元组统计
- [ ] 解析 TCP Option 中的 TOA，写入 LRU_HASH
- [ ] FIN/RST 清理、NLB 网段校验、ringbuf 上报事件
- [ ] 追踪类入门：tracepoint `sched/sched_process_exec`（自己写一个 execsnoop）

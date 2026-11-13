# 原生指标

HTTP 指标使用每个配置代自己的 OpenTelemetry 注册表，记录实际路由的请求计数、错误、处理中请求及耗时、请求大小、响应大小和首字节时间。Admin `/metrics` 使用当前活动注册表；Admin 请求计数跨配置代累计。静态 reverse proxy 上游的健康值来自实际主动、被动健康状态，配置重载指标在真实发布成功后更新。

```json
{"apps":{"http":{"metrics":{"per_host":true,"observe_catchall_hosts":false,"otlp":true},"servers":{"example":{"listen":["127.0.0.1:8080"],"routes":[{"match":[{"path":["/metrics"]}],"handle":[{"handler":"metrics","disable_openmetrics":false}]}]}}}}}
```

`per_host` 启用主机标签；默认仅保留配置中已知的具体主机，其余归为 `_other`。`observe_catchall_hosts` 显式允许观察其他主机，但仍受标签准入限制。旧的 server metrics 设置会在准备全部服务器前合并。`disable_openmetrics` 只控制该 handler 的 OpenMetrics 协商；文本和 Prometheus protobuf 格式仍可用。普通 HTTP 方法规范化为标准方法，其余记为 `OTHER`。

抓取还支持 zstd 压缩和按质量值选择 `text/*` 媒体通配。这是明确的原生增强：原版构建未提供 zstd、忽略 `text/*` 时，所选格式或压缩可能不同，但仍满足请求声明的可接受类型。

响应大小按各路由实际经过的逻辑 writer 分别计量，因此压缩、拦截替换、嵌套路由的内层与外层大小可以不同。有限静态 HEAD 响应按对应逻辑输出计量；指标不会为了 HEAD 读取无限源或重复压缩业务输出。

## 自动导出与数据源

`otlp: true` 在配置代提交后启用自动导出。endpoint、headers、protocol、timeout、compression 和 TLS 材料通过标准 `OTEL_EXPORTER_OTLP_*` / `OTEL_EXPORTER_OTLP_METRICS_*` 环境设置读取；没有 JSON `endpoint` 字段。`OTEL_SERVICE_NAME` 优先于 resource 属性中的 `service.name`。

| 设置 | 行为 |
| --- | --- |
| `OTEL_METRICS_EXPORTER` 未设置或 `otlp` | HTTP/protobuf，或通过 protocol 选择 gRPC；支持 gzip、TLS 根证书及成对的 mTLS 证书和私钥 |
| `OTEL_METRICS_EXPORTER=none` | 不启用自动导出 |
| `OTEL_METRICS_EXPORTER=console` | 输出 Go stdout metric 形状的 JSON；SDK 元数据使用真实 Rust SDK 信息 |
| `OTEL_METRICS_EXPORTER=prometheus` | 独立 Prometheus 监听，默认 `localhost:9464`，host/port 使用 `OTEL_EXPORTER_PROMETHEUS_HOST` / `PORT` |
| `OTEL_METRICS_PRODUCERS` 未设置 | 当前配置代的 Caddy 与原生进程注册表 |
| `OTEL_METRICS_PRODUCERS=prometheus` | 独立的真实原生进程 provider，不混入 HTTP/Admin/重载序列 |
| `OTEL_METRICS_PRODUCERS=none` | 仅 resource，空的 `ScopeMetrics` |

独立 Prometheus exporter 明确使用所选数据源，而不是另一个未连接业务数据的全局注册表。这是原生实现提供可用指标的增强；不将原版 registry 连接造成的空数据归咎于 Prometheus 协议。

HTTP 与 HTTPS 导出支持代理环境设置及 HTTP absolute-form、HTTPS CONNECT 和代理认证。gRPC 使用官方生成的 protobuf 客户端和 tonic 编解码，保留状态、trailers、gzip 和有界瞬态重试。TLS 与 DNS 复用原生 runtime 的解析、系统根证书和签名验证能力。

## 资源与生命周期

以下是不同的额度池，不是一个合并的进程 RSS 上限。

| 资源 | 额度与准入 |
| --- | --- |
| metadata / labels | 进程合计 128 MiB，内部保留 8 MiB 用于候选基础组件换代 |
| 基础组件 | 每代先付 4 MiB，加 resource 输入字节数的 32 倍；resource 属性和 service name 合计最多 128 KiB，基础合计最多 8 MiB |
| TLS 材料 | 独立从同一 metadata 池预付；每文件最多 1 MiB，合计 3 MiB，每次堆增长及证书解析前付费，额度随真实 TLS/连接所有者保留 |
| 已配置主机索引 | 独立预付，最多 2048 个不同主机；不足时保守归入 `_other`，不扩大任意主机标签，也不阻断业务 |
| 动态序列 | 每组最多 2048 个 |
| 请求与帧状态 | 进程合计 64 MiB；独立 Prometheus 端口每条连接先付 256 KiB，最多 128 条，HTTP/1 读缓冲限制 64 KiB |
| 收集与编码工作区 | 进程合计 512 MiB；每次先付 256 MiB，再进行 SDK collect、protobuf 转换或借用快照的流式 JSON 编码 |
| 抓取输出 | 进程合计 128 MiB；每份先付 64 MiB，保留至最后一个输出字节引用释放 |
| OTLP 消息 | protobuf 消息最多 32 MiB；gRPC 在 codec 缓冲区分配前检查长度，之前的 collect/转换也有工作区额度 |
| exporter 设置 | 环境设置文本合计最多 16 KiB；TLS 文件内容另行计量 |

收集工作使用独立的 `min(实际可用 CPU, 4)` 并发，最多 32 个等待者，队列等待上限 2 秒；不改变业务 HTTP/TLS worker 数量。拦截替换仅对 producer 证明已经准备好的内存实体结束内部观测，独立并发最多 `min(CPU, 4)`、上限 10 秒；未知网络或文件源立即丢弃观测并关闭，不为指标额外下载。`Content-Length` 或精确大小提示不是内存实体证明，异步压缩也会移除这一标记。

发送 DATA 的每个实际字节所有者携带额度。收到提前成功响应或导出 future 结束，都不会提前退款。绝对导出期限到达时，原生传输取消实际连接并等待连接任务结束；下一周期可以创建新连接，正常周期则复用连接。保留最多 3 次额外瞬态重试及 `RetryInfo`；前次 DATA 仍被持有时不叠加新的网络发送。HTTP 客户端内部的 507 只表示这一观测准入失败，不是业务响应或伪造的 collector 响应。

中途取消或源出错且未完成的 body 不会记成正常请求完成；成功的空 body 仍正常计量。压力会丢弃新观测并增加计数；指标抓取本身可以返回 503。候选基础或必要 TLS 预算不足时在配置预检阶段拒绝，旧配置继续服务。不会为退款而释放仍被输出 reader、旧业务连接或 exporter 持有的资源。

## 真实运行时数据

Linux 和 macOS 的进程 CPU、RSS、虚拟内存、启动时间、FD 数及限制来自实际系统接口。Linux 网络计数沿用 Go process collector 的进程网络命名空间 `IpExt` 口径，而不是每条连接的独占计数。取值失败时省略相关样本，不用假零代替。

没有 Go GC、goroutine 或 Go heap 的伪数据。额外原生指标包括 `caddy_rust_build_info`、`caddy_runtime_available_parallelism`、`caddy_metrics_observations_dropped_total` 和 `caddy_metrics_export_errors_total`。

Console 使用专属同 binary Rust writer 子进程持有 stdout 写入。native CLI 在任何配置或 runtime 初始化前识别严格内部协议入口；普通库嵌入若未明确注册同 binary helper 能力，console 准备阶段会拒绝，而不会执行未知宿主。每批只有一个固定 helper 参数，编码实体经有界 stdin 协议发送，最多 64 MiB，helper 仅用 16 KiB 栈暂存。进程内所有配置代共用一个有界 writer 准入，先准入再收集，不在 collection worker 上等待 stdout。父进程保留编码实体和额度至子进程真实退出；满管道、调用取消、停止或绝对期限会终止该专属 writer 并等待回收，不更改主进程 stdout flags，也不终止业务进程。取消可能留下已写入管道的部分 JSON；成功完成的记录为完整 JSON。

Console 编码直接借用本批 SDK snapshot，保留它直到编码完成；属性排序仅存放引用，排序缓冲及编码增长都包含在发送前已付的工作区中，不建立完整 JSON DOM。输出字节另随实际 writer 持有其额度。


## 推送导出的 CPU 与 I/O 生命周期

普通 OTLP HTTP/protobuf、gRPC 和 console 推送使用封闭的驻留状态机。快照、SDK 的同步 protobuf/压缩编码、已完成 future 和取消后的大数据析构在原 collection CPU lane 上执行；等待网络、重试计时器或 console 子进程时归还 running permit。已接收批次、等待队列、console 的 try 准入、每代 actor 次序、最终一次收集及原配置的绝对超时保持原语义；没有新增批次并行，也没有为满足测试缩短 flush 时间。

Trace 与 Metrics 只共享具体状态机、字节读者和 unary 编码代码。两者各自持有 registry、退休线程、外部 owner 和原本的 running semaphore；交接检查实际 owner identity、数据域和 running semaphore 的 Arc 身份，不能以同域另一个 owner 的额度或 CPU lane 替代。Metrics 控制元数据、所有最后 Weak 控制块以及一条 requested stack 为 2 MiB 的退休线程，预付到原 Process 的 64 MiB request-state 空间，并同时受其 8 MiB subtype 限额约束。这是同一物理布局的两层准入，不是额外增加 8 MiB 总配额；通常约 2 MiB 常驻、最多 8 MiB 的真实竞争不会扣用 labels、快照 scratch 或编码 output 的额度。线程启动失败使准备失败，不在接收大批次后悄悄改走反应器。

物理 BatchMemory 与控制原 IO 完成、created 时间、deadline 和重试 strong-count 的逻辑 Credit 分离。实际 Bytes 的读者共享不可变 backing；最后读者先释放自己的 backing 引用，再发布 reader0，registry 随后在匹配 CPU permit 下销毁最后大数据并退款。pin 不延长已完成批次的逻辑计时器；真实 DATA 尚被持有时，原 NoReplay 判据仍阻止同批重试。快照升级的 Registry 只在 CPU 临界段暂时持有，驻留 future 和字节 backing 不强持 Registry 或 Process，最后外部 owner Drop 只围栏并唤醒退休线程。

最终 Process 关闭先围栏 Trace 与 Metrics 两域，再并发执行每域自己的 preparation 收据、数据退休、实际 OS join 与 CPU tracker 等待；一域被持住不能延迟另一域自己的关闭和回收。公共连接的最终 shutdown 仍在各代导出 actor flush/关闭之后。显式正常 shutdown 的 stack 信用保留到实际 join 返回；没有可用 runtime 的最后 owner Drop 只证明业务数据退休和线程函数退出，不声称此时 OS 的 stack/TLS/TCB mapping 已回收。

此边界不扩展到公开同步 `Registry::snapshot`、pull scrape 输出的所有析构，也不修复 SDK Processor 在 queue-full/closed 时直接丢弃原 SpanData 的旧边界；不承诺第三方 provider 全 heap 或整个进程 RSS 上限。本轮实际平台验收是 macOS 与 Linux，不能据此宣称其他平台的系统 DNS 物理退休已经验证。

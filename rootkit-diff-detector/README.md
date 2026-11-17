# Rootkit 交叉视图检测服务（rootkit-diff-detector）

针对疑似被植入**内核级隐藏后门**的 Linux 服务器：常规命令（`ps`/`ss`/`lsmod`/`ls`）看不到异常，
是因为 rootkit 专门篡改了这些上层接口的返回。本工具的思路是经典的 **cross-view diff（交叉视图比对）**：

> 同一类信息，从多个**相互独立**的途径各采一份，在服务端互相比对。
> rootkit 能骗过一个接口，很难同时骗过所有接口 ——
> **只在底层来源出现、上层看不见的条目，就是被隐藏的对象。**

仅用于你有授权的环境做防御性检测。

## 检测矩阵

| 类别 | 上层视图（易被骗） | 底层视图（交叉验证） |
|------|------------------|---------------------|
| 进程表 | `ps`、`ls /proc` | `kill -0` 暴力扫描整个 PID 空间（不依赖 /proc 目录列举） |
| 网络连接 | `ss`（netlink） | 直接解析 `/proc/net/{tcp,udp,tcp6,udp6}` |
| 内核模块 | `/proc/modules`（lsmod） | `/sys/module` + `/proc/kallsyms` 符号归属 |
| 文件 | `ls`（libc readdir） | `getdents64` 系统调用直采（绕过 libc / LD_PRELOAD 钩子） |

**严重级别：**
- **HIGH** — 最底层视图可见、上层全部不可见（典型隐藏：摘链表、getdents/netlink 钩子）
- **MEDIUM** — 中层可见、上层不可见（可能是只 hook 了某个用户态工具）
- **LOW** — 噪声：采集间隙对象自然消亡的竞争窗口、内核 builtin 模块（只出现在 `/sys/module`）等

## 目录结构

```
├── src/main/kotlin/detector/
│   ├── Server.kt     # Ktor 服务：REST API + 静态网页，启动时载入 demo/*.json
│   ├── Analyzer.kt   # 交叉视图比对核心（视图分级 + 差异分类 + 证据生成）
│   ├── Store.kt      # 内存快照仓库（演示用，重启即清空）
│   └── Model.kt      # 快照 / 发现 / 证据 数据模型
├── src/main/resources/static/index.html   # 网页端（原生 JS，无外部依赖）
├── collector/collect.sh                   # 被检机器上运行的采集脚本（bash）
├── demo/
│   ├── infected-snapshot.json  # 模拟中招机器 web-01：藏了进程/端口/模块/文件
│   └── clean-snapshot.json     # 干净机器 db-01（含一条 builtin 模块低危噪声作对照）
└── build.gradle.kts
```

## 运行

需要 JDK 17+ 与 Gradle 8+：

```bash
cd rootkit-diff-detector
gradle run                 # 或先 gradle wrapper 生成 ./gradlew 再用它
# 打开 http://127.0.0.1:8080 —— 已自动载入 demo/ 下两份演示快照
```

环境变量：`PORT`（默认 8080）、`DEMO_DIR`（默认 `demo`，设为不存在的目录可关闭演示数据）。

## 在被检机器上采集

```bash
# 采集并生成 JSON 文件
sudo ./collector/collect.sh -o snap.json

# 采集并直接上传到检测服务
sudo ./collector/collect.sh -s http://检测服务器:8080

# 自定义文件视图的监控目录
sudo WATCH_DIRS="/tmp /var/tmp /dev/shm /etc /usr/lib /opt/app" ./collector/collect.sh
```

建议用 `cron`/`systemd timer` 定时采集上传，多轮比对可排除 LOW 级竞争噪声
（真正的隐藏对象会**每一轮**都出现）。

也可以手动提交：网页左下角粘贴快照 JSON，或

```bash
curl -X POST -H 'Content-Type: application/json' --data-binary @snap.json \
  http://127.0.0.1:8080/api/snapshots
```

## API

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/snapshots` | 快照列表（含各级发现数） |
| POST | `/api/snapshots` | 提交快照，立即返回比对统计 |
| GET  | `/api/snapshots/{id}` | 快照原文 + 全部发现与证据 |
| GET  | `/api/findings` | 跨快照聚合的全部发现 |

## 快照格式

```json
{
  "host": "web-01",
  "collectedAt": "2026-11-18T03:12:44Z",
  "categories": {
    "processes": {"views": {"ps": [{"id": "1", "label": "systemd", "detail": "..."}], "pidscan": [...]}},
    "network":   {"views": {"ss": [...], "procnet": [...]}},
    "modules":   {"views": {"proc_modules": [...], "sysfs": [...], "kallsyms": [...]}},
    "files":     {"views": {"ls": [...], "getdents": [...]}}
  }
}
```

每个条目 `id` 是比对键（PID、`协议:端口`、模块名、文件路径）。类别和视图名可扩展，
`Analyzer.kt` 里的 `specs` 表登记各视图的层级（0 = 最底层），未登记的视图按中层处理。

## 演示数据说明

`demo/infected-snapshot.json` 模拟中招机器 web-01，服务端会报出 5 条 HIGH：

- **进程 1337** — `kill -0` 扫描发现存活，但 `/proc/1337` 不存在、`ps` 不可见
- **tcp:4444** — `/proc/net/tcp` 里存在 LISTEN 套接字（`00000000:115C`），`ss` 未报告
- **evillkm** — 出现在 `/sys/module` 且 kallsyms 有 312 个符号归属它，但 `/proc/modules` 没有（摘链）
- **/usr/lib/.xhide、/dev/shm/.kworker** — `getdents64` 直采可见，`ls` 不可见

另有 1 条 LOW（`intel_pstate` 只出现在 `/sys/module`）演示内置模块噪声；
`demo/clean-snapshot.json` 则只有这一条噪声，用于对照。

## 局限性与加固方向

- **强内核 rootkit 可 hook 全部用户态通道**（包括 getdents64 与 /proc/net 读取）。
  更彻底的方案：eBPF/内核探针旁路采集、从虚拟化层（VMI）带外取数、只读挂载的已知良好二进制。
- **采集非原子**：进程/连接在采集间隙生灭会造成 LOW 级竞争噪声，务必多轮比对。
- **网络视图以 `协议:端口` 为键**，同端口不同地址会合并；如需区分可在 `Analyzer.kt` 调整键的构造。
- 文件视图只覆盖 `WATCH_DIRS`，且换行符等特殊文件名会破坏行式解析（真实部署建议改用
  长度前缀或 NUL 分隔的编码）。
- 当前为内存存储，重启即丢；生产化可接 PostgreSQL/SQLite 并保留历史快照做趋势比对。

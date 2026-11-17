package detector

import kotlinx.serialization.Serializable

/** 快照中的一个条目：一个进程 / 一条连接 / 一个模块 / 一个文件 */
@Serializable
data class Entry(
    val id: String,             // 比对键：pid、"tcp:4444"、模块名、文件路径
    val label: String = "",     // 展示名：进程名、模块名、文件名……
    val detail: String = ""     // 采集侧附带的原始证据
)

/** 同一类信息、来自不同途径（视图）的多份采集结果 */
@Serializable
data class CategorySnapshot(
    val views: Map<String, List<Entry>> = emptyMap()
)

/** 一台机器一次提交的完整快照 */
@Serializable
data class Snapshot(
    val host: String,
    val collectedAt: String = "",
    val categories: Map<String, CategorySnapshot> = emptyMap()
)

/** 一条证据：某个视图是否看到了该对象 */
@Serializable
data class Evidence(
    val view: String,
    val level: Int,             // 视图层级，0 = 最接近内核/最底层
    val seen: Boolean,
    val detail: String = ""
)

/** 比对结论：一个疑似被隐藏的对象 */
@Serializable
data class Finding(
    val category: String,
    val categoryLabel: String,
    val objectId: String,
    val label: String,
    val severity: String,       // HIGH / MEDIUM / LOW
    val presentIn: List<String>,
    val missingFrom: List<String>,
    val explanation: String,
    val evidence: List<Evidence>
)

@Serializable
data class SnapshotSummary(
    val id: String,
    val host: String,
    val collectedAt: String,
    val receivedAt: String,
    val high: Int,
    val medium: Int,
    val low: Int
)

@Serializable
data class SnapshotDetail(
    val id: String,
    val host: String,
    val collectedAt: String,
    val receivedAt: String,
    val snapshot: Snapshot,
    val findings: List<Finding>
)

@Serializable
data class IngestResult(
    val id: String,
    val host: String,
    val findings: Int,
    val high: Int,
    val medium: Int,
    val low: Int
)

/** 跨快照聚合视图里的一条发现（附带来源快照信息） */
@Serializable
data class FindingView(
    val snapshotId: String,
    val host: String,
    val collectedAt: String,
    val category: String,
    val categoryLabel: String,
    val objectId: String,
    val label: String,
    val severity: String,
    val presentIn: List<String>,
    val missingFrom: List<String>,
    val explanation: String,
    val evidence: List<Evidence>
)

package detector

import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.http.content.staticResources
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import kotlinx.serialization.json.Json
import java.io.File

val json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
}

fun main() {
    val store = Store()
    loadDemoData(store)

    val port = System.getenv("PORT")?.toIntOrNull() ?: 8080
    println("rootkit-diff-detector 已启动: http://127.0.0.1:$port")
    embeddedServer(Netty, port = port) { appModule(store) }.start(wait = true)
}

fun Application.appModule(store: Store) {
    install(ContentNegotiation) { json(json) }

    routing {
        // 网页端（src/main/resources/static/index.html）
        staticResources("/", "static")

        route("/api") {
            // 快照列表（含各严重级发现数）
            get("/snapshots") {
                call.respond(store.list().map { it.toSummary() })
            }

            // 采集端提交快照，立即返回比对结论统计
            post("/snapshots") {
                val snapshot = call.receive<Snapshot>()
                val record = store.add(snapshot)
                call.respond(record.toIngestResult())
            }

            // 单个快照的完整内容 + 全部发现与证据
            get("/snapshots/{id}") {
                val record = store.get(call.parameters["id"] ?: "")
                if (record == null) {
                    call.respond(HttpStatusCode.NotFound, mapOf("error" to "snapshot not found"))
                } else {
                    call.respond(record.toDetail())
                }
            }

            // 跨快照聚合的全部发现
            get("/findings") {
                call.respond(
                    store.list().flatMap { r -> r.findings.map { f -> f.toView(r) } }
                )
            }
        }
    }
}

/** 启动时加载 demo/*.json（若存在），让网页打开即有演示数据。用 DEMO_DIR 覆盖路径。 */
private fun loadDemoData(store: Store) {
    val dir = File(System.getenv("DEMO_DIR") ?: "demo")
    if (!dir.isDirectory) return
    val files = dir.listFiles { f -> f.extension == "json" }?.sortedBy { it.name } ?: return
    for (f in files) {
        try {
            val snapshot = json.decodeFromString<Snapshot>(f.readText())
            val record = store.add(snapshot)
            println(
                "已载入演示快照 ${f.name}: host=${snapshot.host}, " +
                    "发现 ${record.findings.size} 条（HIGH ${record.findings.count { it.severity == "HIGH" }}）"
            )
        } catch (e: Exception) {
            System.err.println("跳过无法解析的演示文件 ${f.name}: ${e.message}")
        }
    }
}

private fun Store.Record.toSummary() = SnapshotSummary(
    id = id,
    host = snapshot.host,
    collectedAt = snapshot.collectedAt,
    receivedAt = receivedAt,
    high = findings.count { it.severity == "HIGH" },
    medium = findings.count { it.severity == "MEDIUM" },
    low = findings.count { it.severity == "LOW" }
)

private fun Store.Record.toIngestResult() = IngestResult(
    id = id,
    host = snapshot.host,
    findings = findings.size,
    high = findings.count { it.severity == "HIGH" },
    medium = findings.count { it.severity == "MEDIUM" },
    low = findings.count { it.severity == "LOW" }
)

private fun Store.Record.toDetail() = SnapshotDetail(
    id = id,
    host = snapshot.host,
    collectedAt = snapshot.collectedAt,
    receivedAt = receivedAt,
    snapshot = snapshot,
    findings = findings
)

private fun Finding.toView(r: Store.Record) = FindingView(
    snapshotId = r.id,
    host = r.snapshot.host,
    collectedAt = r.snapshot.collectedAt,
    category = category,
    categoryLabel = categoryLabel,
    objectId = objectId,
    label = label,
    severity = severity,
    presentIn = presentIn,
    missingFrom = missingFrom,
    explanation = explanation,
    evidence = evidence
)

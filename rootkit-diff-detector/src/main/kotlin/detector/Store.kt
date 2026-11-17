package detector

import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/** 内存快照仓库：收到快照即完成比对并缓存结论。演示用，重启即清空。 */
class Store {

    data class Record(
        val id: String,
        val snapshot: Snapshot,
        val receivedAt: String,
        val findings: List<Finding>
    )

    private val seq = AtomicInteger(0)
    private val records = CopyOnWriteArrayList<Record>()

    fun add(snapshot: Snapshot): Record {
        val record = Record(
            id = "snap-${seq.incrementAndGet()}",
            snapshot = snapshot,
            receivedAt = Instant.now().toString(),
            findings = Analyzer.analyze(snapshot)
        )
        records += record
        return record
    }

    fun list(): List<Record> = records.toList()

    fun get(id: String): Record? = records.firstOrNull { it.id == id }
}

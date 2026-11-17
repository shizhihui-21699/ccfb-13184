package detector

/**
 * 交叉视图比对（cross-view diff）核心：
 *
 * 同一类系统信息，用「上层工具」和「底层接口」各采一份。
 * 用户态 rootkit 通常只 hook 上层接口（libc、ps/ls 等），
 * 内核态 rootkit 为了不留痕迹会篡改某一两个特定内核接口，
 * 但很难同时骗过所有独立的数据通道。
 *
 * 因此：在底层视图可见、却对上层视图不可见的条目，即为疑似被隐藏的对象。
 */
object Analyzer {

    private data class CategorySpec(
        val label: String,
        val levels: Map<String, Int>, // 视图名 -> 层级，数字越小越接近内核
    )

    private val specs = mapOf(
        "processes" to CategorySpec(
            "进程表",
            mapOf("pidscan" to 0, "procfs" to 1, "ps" to 2, "top" to 2, "htop" to 2)
        ),
        "network" to CategorySpec(
            "网络连接",
            mapOf("procnet" to 0, "ss" to 1, "netstat" to 1, "lsof" to 1)
        ),
        "modules" to CategorySpec(
            "内核模块",
            mapOf("kallsyms" to 0, "sysfs" to 1, "proc_modules" to 2, "lsmod" to 2, "modinfo" to 2)
        ),
        "files" to CategorySpec(
            "文件",
            mapOf("getdents" to 0, "ls" to 1, "find" to 1)
        ),
    )

    fun analyze(snapshot: Snapshot): List<Finding> {
        val findings = mutableListOf<Finding>()
        for ((category, catSnap) in snapshot.categories) {
            val spec = specs[category] ?: CategorySpec(category, emptyMap())
            findings += analyzeCategory(category, spec, catSnap)
        }
        return findings.sortedWith(
            compareBy({ severityRank(it.severity) }, { it.category }, { it.objectId })
        )
    }

    private fun analyzeCategory(
        category: String,
        spec: CategorySpec,
        cat: CategorySnapshot
    ): List<Finding> {
        val viewNames = cat.views.keys.toList()
        if (viewNames.size < 2) return emptyList()

        val levelOf = { v: String -> spec.levels[v] ?: 1 }
        val byView: Map<String, Map<String, Entry>> =
            cat.views.mapValues { (_, entries) -> entries.associateBy { it.id } }

        val allIds = LinkedHashSet<String>()
        cat.views.values.forEach { entries -> entries.forEach { allIds += it.id } }

        val out = mutableListOf<Finding>()
        for (id in allIds) {
            val present = viewNames.filter { byView[it]?.containsKey(id) == true }
            val missing = viewNames.filter { byView[it]?.containsKey(id) != true }
            if (missing.isEmpty()) continue // 所有视图一致，正常

            val minPresentLevel = present.minOf { levelOf(it) }
            // 比「最底层的目击者」更上层的视图里，有哪些没看到这个对象
            val hiddenFrom = missing.filter { levelOf(it) > minPresentLevel }

            val severity: String
            val explanation: String
            when {
                // 特判：内核模块只出现在 /sys/module —— 大概率是 builtin 内置模块，属正常噪声
                category == "modules" && present.toSet() == setOf("sysfs") -> {
                    severity = "LOW"
                    explanation = "模块「$id」仅出现在 /sys/module。内核内置(builtin)模块也会出现在 " +
                        "/sys/module 而不在 /proc/modules，多半为正常情况；但若它同时出现在 kallsyms " +
                        "视图（说明是已加载的 LKM），则需高度警惕。"
                }
                // 经典隐藏模式：底层可见、上层不可见
                hiddenFrom.isNotEmpty() -> {
                    severity = if (minPresentLevel == 0) "HIGH" else "MEDIUM"
                    explanation = "「$id」在底层视图 [${present.joinToString("、")}] 中可见，" +
                        "却对上层视图 [${hiddenFrom.joinToString("、")}] 不可见 —— 符合${spec.label}隐藏特征。" +
                        "rootkit 常见手法：篡改/proc 读取结果、getdents64/netlink 钩子、链表摘除(DKOM)。"
                }
                // 反向不一致：上层看到、底层没有 —— 多为采集间隙对象自然消亡（竞争窗口）
                else -> {
                    severity = "LOW"
                    explanation = "「$id」在视图间不一致（出现于 [${present.joinToString("、")}]，" +
                        "缺失于 [${missing.joinToString("、")}]），但不是「底层可见、上层不可见」的模式，" +
                        "可能是采集间隙对象自然创建/销毁（竞争窗口）。建议多轮采集复核，持续出现才需关注。"
                }
            }

            val label = present.asSequence()
                .mapNotNull { byView[it]?.get(id) }
                .firstOrNull { it.label.isNotEmpty() }?.label ?: ""

            val evidence = viewNames.map { v ->
                val e = byView[v]?.get(id)
                Evidence(view = v, level = levelOf(v), seen = e != null, detail = e?.detail ?: "")
            }

            out += Finding(
                category = category,
                categoryLabel = spec.label,
                objectId = id,
                label = label,
                severity = severity,
                presentIn = present,
                missingFrom = missing,
                explanation = explanation,
                evidence = evidence
            )
        }
        return out
    }

    private fun severityRank(s: String) = when (s) {
        "HIGH" -> 0
        "MEDIUM" -> 1
        else -> 2
    }
}

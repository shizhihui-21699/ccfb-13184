#!/usr/bin/env bash
#
# collect.sh — 多途径系统状态快照采集器（交叉视图比对用）
#
# 对同一类信息，用「上层工具」和「底层接口」各采一份，交给服务端互相比对：
#
#   类别     上层视图              底层视图（更难被 rootkit 同时骗过）
#   -------  --------------------  ------------------------------------------
#   进程     ps / ls /proc         kill -0 暴力 PID 扫描（不读 /proc 目录列举）
#   网络     ss（netlink）          直接解析 /proc/net/{tcp,udp,tcp6,udp6}
#   模块     /proc/modules         /sys/module + /proc/kallsyms 符号归属
#   文件     ls                    getdents64 系统调用直采（绕过 libc/LD_PRELOAD 钩子）
#
# 建议以 root 运行：pidscan 靠 kill -0 对非自身进程返回 EPERM 来判断“存在但无权”，
# 非 root 会漏判别人的进程。仅用于你有授权的环境。
#
# 用法:
#   ./collect.sh                        # 生成 snapshot-<host>-<时间>.json
#   ./collect.sh -o out.json            # 指定输出文件
#   ./collect.sh -s http://127.0.0.1:8080   # 采集并直接上传到检测服务
#   WATCH_DIRS="/tmp /etc /usr/lib" ./collect.sh
#
set -euo pipefail

SERVER=""
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out)    OUT="$2"; shift 2 ;;
    -s|--server) SERVER="$2"; shift 2 ;;
    -h|--help)   sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

WATCH_DIRS="${WATCH_DIRS:-/tmp /var/tmp /dev/shm /etc /usr/local/bin /usr/local/lib /usr/lib /lib}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# JSON 字符串转义（去掉控制字符，转义反斜杠和引号）
jesc() { tr -d '\000-\010\013\014\016-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

echo "[*] 采集进程视图..."

# 视图 ps（上层：ps 读取 /proc 后经 libc 处理）
ps -eo pid=,comm=,args= 2>/dev/null | while read -r pid comm args; do
  [ -n "${pid:-}" ] || continue
  printf '%s\t%s\t%s\n' "$pid" "$comm" "$args"
done > "$TMP/ps.tsv"

# 视图 procfs（中层：直接列 /proc 目录）
for d in /proc/[0-9]*; do
  [ -d "$d" ] || continue
  pid=${d#/proc/}
  comm=$(cat "$d/comm" 2>/dev/null || echo "?")
  exe=$(readlink "$d/exe" 2>/dev/null || echo "?")
  printf '%s\t%s\texe=%s\n' "$pid" "$comm" "$exe"
done > "$TMP/procfs.tsv"

# 视图 pidscan（底层：kill -0 暴力扫描整个 PID 空间，不依赖 /proc 目录列举。
# 若某 PID 存活但 /proc/<pid> 不可读，正是典型的隐藏痕迹。）
PID_MAX=$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo 32768)
if command -v python3 >/dev/null 2>&1; then
  python3 - "$PID_MAX" <<'PYEOF' > "$TMP/pidscan.tsv"
import os, sys
pid_max = int(sys.argv[1])
for pid in range(1, pid_max + 1):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        continue
    except PermissionError:
        pass  # 存在但无权发信号（非 root 时他人的进程）
    try:
        with open(f"/proc/{pid}/comm") as f:
            comm = f.read().strip()
    except Exception:
        comm = "?"  # 进程活着但 /proc 条目读不到 —— 强隐藏信号
    print(f"{pid}\t{comm}\tkill -0 存活")
PYEOF
else
  echo "[!] 未找到 python3，pidscan 退化为 bash 慢速扫描（上限 65536）" >&2
  lim=$PID_MAX; [ "$lim" -gt 65536 ] && lim=65536
  : > "$TMP/pidscan.tsv"
  for ((pid=1; pid<=lim; pid++)); do
    if kill -0 "$pid" 2>/dev/null; then
      comm=$(cat "/proc/$pid/comm" 2>/dev/null || echo "?")
      printf '%s\t%s\tkill -0 存活\n' "$pid" "$comm" >> "$TMP/pidscan.tsv"
    fi
  done
fi

echo "[*] 采集网络连接视图..."

# 视图 ss（上层：netlink inet_diag）；无 ss 时退化为 netstat
NET_VIEW=ss
if command -v ss >/dev/null 2>&1; then
  ss -tunaH 2>/dev/null | awk '$2=="LISTEN"||$2=="ESTAB" {
    n=split($5,a,":"); port=a[n];
    printf "%s:%s\t%s:%s\tstate=%s local=%s peer=%s\n", $1,port,$1,port,$2,$5,$6
  }' > "$TMP/ss.tsv"
elif command -v netstat >/dev/null 2>&1; then
  NET_VIEW=netstat
  netstat -tuna 2>/dev/null | awk 'NR>2 && ($6=="LISTEN"||$6=="ESTABLISHED") {
    n=split($4,a,":"); port=a[n];
    printf "%s:%s\t%s:%s\tstate=%s local=%s peer=%s\n", $1,port,$1,port,$6,$4,$5
  }' > "$TMP/netstat.tsv"
else
  echo "[!] 无 ss/netstat，跳过上层网络视图" >&2
fi

# 视图 procnet（底层：直接解析 /proc/net/*，十六进制地址端口）
: > "$TMP/procnet.tsv"
for f in /proc/net/tcp /proc/net/udp /proc/net/tcp6 /proc/net/udp6; do
  [ -r "$f" ] || continue
  proto=$(basename "$f"); proto=${proto%6}   # tcp6->tcp，与 ss 的 netid 对齐
  tail -n +2 "$f" | while read -r _sl local rem st _rest; do
    # 只保留 LISTEN(0A) 与 ESTABLISHED(01)，过滤 TIME_WAIT 等瞬时状态降噪
    [ "$st" = "0A" ] || [ "$st" = "01" ] || continue
    hexport=${local##*:}
    port=$((16#$hexport))
    printf '%s:%s\t%s:%s\tstate=%s local_hex=%s remote_hex=%s\n' \
      "$proto" "$port" "$proto" "$port" "$st" "$local" "$rem"
  done >> "$TMP/procnet.tsv"
done

echo "[*] 采集内核模块视图..."

# 视图 proc_modules（上层列表，rootkit 摘链表后首先从这里消失）
awk '{printf "%s\t%s\tsize=%s used_by=%s\n",$1,$1,$2,$4}' /proc/modules > "$TMP/proc_modules.tsv" 2>/dev/null || : > "$TMP/proc_modules.tsv"

# 视图 sysfs（/sys/module；注意：内核内置模块也会出现，服务端会按低危噪声处理）
ls /sys/module 2>/dev/null | while IFS= read -r m; do
  printf '%s\t%s\t/sys/module/%s\n' "$m" "$m" "$m"
done > "$TMP/sysfs.tsv"

# 视图 kallsyms（底层：/proc/kallsyms 中符号的 [模块] 归属；内置模块不带标注，
# 出现在这里的一定是已加载的 LKM —— 若它不在 /proc/modules，即被摘链）
grep -o '\[[^]]*\]' /proc/kallsyms 2>/dev/null | tr -d '[]' | sort -u | while IFS= read -r m; do
  [ -n "$m" ] && printf '%s\t%s\tkallsyms 符号归属\n' "$m" "$m"
done > "$TMP/kallsyms.tsv" || : > "$TMP/kallsyms.tsv"

echo "[*] 采集文件视图（目录: $WATCH_DIRS）..."

: > "$TMP/ls.tsv"
GETDENTS_VIEW=getdents
command -v python3 >/dev/null 2>&1 || GETDENTS_VIEW=find
: > "$TMP/$GETDENTS_VIEW.tsv"

for d in $WATCH_DIRS; do
  [ -d "$d" ] || continue
  # 视图 ls（上层：libc readdir，可被 LD_PRELOAD 钩子过滤）
  ls -A1 "$d" 2>/dev/null | while IFS= read -r name; do
    printf '%s/%s\t%s\tls -A1 %s\n' "$d" "$name" "$name" "$d"
  done >> "$TMP/ls.tsv"
  # 视图 getdents（底层：直接发起 getdents64 系统调用，绕过 libc/LD_PRELOAD）
  if [ "$GETDENTS_VIEW" = "getdents" ]; then
    python3 - "$d" <<'PYEOF' >> "$TMP/getdents.tsv"
import ctypes, os, sys
d = sys.argv[1]
# x86_64 / aarch64 的 getdents64 系统调用号均为 217
SYS_getdents64 = 217
libc = ctypes.CDLL(None, use_errno=True)
fd = libc.open(d.encode(), os.O_RDONLY | os.O_DIRECTORY)
if fd < 0:
    sys.exit(0)
buf = ctypes.create_string_buffer(65536)
names = []
while True:
    n = libc.syscall(SYS_getdents64, fd, buf, 65536)
    if n <= 0:
        break
    off = 0
    while off < n:
        # linux_dirent64: d_ino(8) d_off(8) d_reclen(2) d_type(1) d_name[]
        reclen = int.from_bytes(buf[off+16:off+18], "little")
        if reclen <= 0:
            break
        name = buf[off+19:off+reclen].split(b"\0")[0].decode("utf-8", "replace")
        if name not in (".", ".."):
            names.append(name)
        off += reclen
libc.close(fd)
for name in names:
    print(f"{d}/{name}\t{name}\tgetdents64 直采 {d}")
PYEOF
  else
    # 无 python3 时退化：find 与 ls 至少是不同二进制/不同代码路径
    find "$d" -mindepth 1 -maxdepth 1 -printf '%p\t%f\tfind 直采\n' 2>/dev/null >> "$TMP/find.tsv"
  fi
done

echo "[*] 组装 JSON..."

emit_entries() { # $1 = tsv 文件 -> JSON 数组元素
  local first=1 id label detail
  while IFS=$'\t' read -r id label detail; do
    [ -n "${id:-}" ] || continue
    [ $first -eq 0 ] && printf ','
    first=0
    printf '{"id":"%s","label":"%s","detail":"%s"}' \
      "$(printf '%s' "$id" | jesc)" \
      "$(printf '%s' "${label:-}" | jesc)" \
      "$(printf '%s' "${detail:-}" | jesc)"
  done < "$1"
}

emit_category() { # $1 = 类别名，其余参数 = 视图 tsv 文件（文件名为视图名）
  local cat=$1; shift
  printf '"%s":{"views":{' "$cat"
  local first=1 f v
  for f in "$@"; do
    [ -f "$f" ] || continue
    v=$(basename "$f" .tsv)
    [ $first -eq 0 ] && printf ','
    first=0
    printf '"%s":[' "$v"
    emit_entries "$f"
    printf ']'
  done
  printf '}}'
}

HOST_TAG=$(hostname -f 2>/dev/null || hostname)
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[ -n "$OUT" ] || OUT="snapshot-${HOST_TAG%%.*}-$(date -u +%Y%m%d-%H%M%S).json"

{
  printf '{"host":"%s","collectedAt":"%s","categories":{' "$(printf '%s' "$HOST_TAG" | jesc)" "$TS"
  emit_category processes "$TMP/ps.tsv" "$TMP/procfs.tsv" "$TMP/pidscan.tsv"
  printf ','
  emit_category network "$TMP/$NET_VIEW.tsv" "$TMP/procnet.tsv"
  printf ','
  emit_category modules "$TMP/proc_modules.tsv" "$TMP/sysfs.tsv" "$TMP/kallsyms.tsv"
  printf ','
  emit_category files "$TMP/ls.tsv" "$TMP/$GETDENTS_VIEW.tsv"
  printf '}}'
} > "$OUT"

echo "[+] 快照已生成: $OUT"

if [ -n "$SERVER" ]; then
  echo "[*] 上传到 $SERVER/api/snapshots ..."
  curl -sS -X POST -H 'Content-Type: application/json' --data-binary @"$OUT" \
    "$SERVER/api/snapshots"
  echo
fi

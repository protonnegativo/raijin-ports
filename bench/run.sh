#!/usr/bin/env bash
# Reproducible token benchmark: naabu + nmap output vs raijin-ports output on the same open ports.
#
# usage: bench/run.sh [workdir]
#        LIVE=1 bench/run.sh [workdir]   start the local lab, rescan it and refresh bench/fixtures first
# needs: go, python3 with tiktoken (pip install tiktoken); LIVE=1 also needs naabu and nmap
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: PY=<python with tiktoken>, NAABU=<path>, NMAP=<path>
#
# Safety: LIVE=1 scans only the lab it starts itself (bench/lab.py) on loopback addresses (127.0.0.0/8),
# ports 19000-19999, with a TCP connect scan at 500 packets per second. It stops the lab when it exits.
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
PY=${PY:-python3}
NAABU=${NAABU:-naabu}
NMAP=${NMAP:-nmap}
mkdir -p "$W"
echo "workdir: $W"

# Lab: one python process with fake services on loopback addresses (see lab.py for the kinds).
# noisy:    27 hosts. localhost and 20 more with the same two nginx ports, 4 with one Apache port, 1 with
#           the two nginx ports plus an Apache port no other host has, and 1 that accepts a connection
#           on 200 ports and closes it at once (nmap: tcpwrapped).
# findings: 6 hosts with Redis, MySQL, Memcached, Elasticsearch, the Docker API, SSH on a non-standard
#           port, VNC and Telnet next to nginx, and one Apache port no other host has.
noisy=(127.0.0.1:19080=nginx 127.0.0.1:19081=nginx)
noisy_targets=(localhost)
for i in $(seq 10 29) 34; do
  noisy+=(127.0.0.$i:19080=nginx 127.0.0.$i:19081=nginx); noisy_targets+=(127.0.0.$i)
done
for i in 30 31 32 33; do noisy+=(127.0.0.$i:19080=apache); noisy_targets+=(127.0.0.$i); done
noisy+=(127.0.0.34:19777=apache 127.0.0.35:19500-19699=closer); noisy_targets+=(127.0.0.35)
findings=(
  127.0.0.2:19080=nginx 127.0.0.2:19022=ssh 127.0.0.2:19379=redis
  127.0.0.3:19306=mysql 127.0.0.3:19211=memcached 127.0.0.3:19590=vnc 127.0.0.3:19023=telnet
  127.0.0.4:19375=docker 127.0.0.4:19920=elastic 127.0.0.4:19080=nginx
  127.0.0.5:19080=nginx 127.0.0.5:19022=ssh 127.0.0.5:19379=redis
  127.0.0.6:19080=nginx
  127.0.0.7:19080=nginx 127.0.0.7:19888=apache
)
findings_targets=(127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5 127.0.0.6 127.0.0.7)
printf '127.0.0.0/8\nlocalhost\n' > "$W/scope.txt"

(cd "$ROOT" && go build -o "$W/raijin-ports" ./cmd/raijin-ports)

# batches prints one line per nmap run raijin-ports makes: the port list, then the IPs that share it.
batches() {
  python3 -c 'import json,sys
ports = {}
for l in open(sys.argv[1]):
    l = l.strip()
    if l.startswith("{"):
        e = json.loads(l)
        ports.setdefault(e["ip"], set()).add(e["port"])
by = {}
for ip in sorted(ports):
    by.setdefault(",".join(map(str, sorted(ports[ip]))), []).append(ip)
for p, ips in by.items():
    print(p, *ips)' "$1"
}

if [ "${LIVE:-}" = 1 ]; then
  for spec in "${noisy[@]}" "${findings[@]}"; do
    ports=${spec#*:}; ports=${ports%%=*}
    for port in $(seq "${ports%%-*}" "${ports##*-}"); do
      if ss -ltn | grep -q ":$port "; then echo "port $port is busy; free it first" >&2; exit 1; fi
    done
  done
  python3 "$HERE/lab.py" "${noisy[@]}" "${findings[@]}" > "$W/lab.log" 2>&1 &
  echo $! > "$W/pids"
  trap '[ -f "$W/pids" ] && xargs kill < "$W/pids" 2>/dev/null || true' EXIT
  sleep 2
  for name in noisy findings; do
    f=$HERE/fixtures/$name
    mkdir -p "$f"
    eval 'printf "%s\n" "${'$name'_targets[@]}"' > "$W/$name.targets"
    # raijin-ports runs naabu (-s c -json) and nmap (-sT -sV -oX -) and saves their output as raw: that
    # file is the fixture.
    "$W/raijin-ports" --naabu "$NAABU" --nmap "$NMAP" --scope "$W/scope.txt" -l "$W/$name.targets" \
      -p 19000-19999 --rate 500 --raw "$f/raw.txt" > "$W/$name.live.json"
    # naabu and nmap as an agent would run them, in text, on the same targets and ports.
    "$NAABU" -l "$W/$name.targets" -p 19000-19999 -s c -rate 500 -silent -nc -duc -no-stdin > "$f/naabu.txt"
    : > "$f/nmap.txt"
    batches "$f/raw.txt" | while read -r ports ips; do
      # shellcheck disable=SC2086
      "$NMAP" -sT -sV -Pn -n -p "$ports" $ips < /dev/null >> "$f/nmap.txt"
    done
  done
fi

scenario() {
  local name=$1
  local f=$HERE/fixtures/$name o=$W/$name
  mkdir -p "$o"
  # raijin-ports replays raw with --input, so every row sees the same ports and services.
  (cd "$ROOT" && "$W/raijin-ports" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.txt") > "$o/raijin.json"
  (cd "$ROOT" && "$W/raijin-ports" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.txt" --pretty) > "$o/raijin_pretty.json"
  (cd "$ROOT" && "$W/raijin-ports" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.txt" --format table) > "$o/raijin_table.txt"
  echo; echo "## $name: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' "$o/raijin.json")"; echo
  python3 "$HERE/verify.py" "$f/raw.txt" "$o/raijin.json"
  "$PY" "$HERE/count_tokens.py" \
    "naabu -json + nmap -oX=$f/raw.txt" \
    "naabu text + nmap text=$f/naabu.txt+$f/nmap.txt" \
    "raijin-ports JSON (default)=$o/raijin.json" \
    "raijin-ports --pretty=$o/raijin_pretty.json" \
    "raijin-ports --format table=$o/raijin_table.txt"
}

scenario noisy
scenario findings

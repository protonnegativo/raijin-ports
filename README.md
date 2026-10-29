# ⚡ Raijin Ports

[![CI](https://github.com/protonnegativo/raijin-ports/actions/workflows/ci.yml/badge.svg)](https://github.com/protonnegativo/raijin-ports/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/protonnegativo/raijin-ports)](https://github.com/protonnegativo/raijin-ports/releases/latest)
[![License: MIT](https://img.shields.io/github/license/protonnegativo/raijin-ports)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/protonnegativo/raijin-ports.svg)](https://pkg.go.dev/github.com/protonnegativo/raijin-ports)
[![Go Report Card](https://goreportcard.com/badge/github.com/protonnegativo/raijin-ports)](https://goreportcard.com/report/github.com/protonnegativo/raijin-ports)

**naabu + nmap for AI agents: every open port with its service, hosts with the same ports collapsed, exposed databases and admin services ranked first.**

`raijin-ports` is a tool of **Raijin**, an arsenal of offensive security tools built for AI agents. It runs [naabu](https://github.com/projectdiscovery/naabu) to find open ports and [nmap](https://nmap.org) service detection (`-sV`) on the ports it found, and returns the **Raijin Schema**: one compact JSON where hosts with the same open ports and services share one group, exposed databases, admin APIs and remote admin services are ranked findings, a port only one host has open is flagged, and anything it had to cut is counted.

## Why not just run naabu and nmap?

They are built for people and pipelines. An agent pays for every byte it reads. naabu's JSON is one line per port with a timestamp, and it writes every port twice. nmap's XML repeats the address, the state, the reason, the CPEs and the scan metadata for every port, and a port it cannot identify carries a fingerprint of a few kilobytes. Their text output is shorter, but it is one block per host, so 22 hosts with the same two ports are 22 copies of the same lines.

Here are the same ports, with the same services, read by an agent (tokens, `o200k_base`):

```
Noisy: 27 hosts, 249 open ports, 22 hosts with the same two web ports
  raijin-ports    ▏                          459 tokens
  engines text    ███▎                     6,981 tokens
  engines JSON    ████████████████████    41,933 tokens

Findings: 6 hosts, 16 open ports, 9 findings (5 high, 3 medium, 1 low)
  raijin-ports    ███                        780 tokens
  engines text    ████▌                    1,175 tokens
  engines JSON    ████████████████████     5,151 tokens
```

raijin-ports reads **91×** fewer tokens than the engines' JSON (`naabu -json` plus `nmap -oX`) on the noisy run and **6.6×** fewer on the findings run. Each scenario's bars are drawn to scale against the JSON.

- **Nothing is lost.** Every open port naabu found is in the output, with the service, product, version and extra information nmap identified on it. `bench/verify.py` checked 265 naabu results and 265 nmap services in the two scenarios and none were missing.
- **The real problems come first.** Redis, MySQL, Elasticsearch and the Docker API are high, VNC, Telnet and SSH on an odd port are medium, and a port only one host has open is low. 22 web servers with the same two ports are one group.
- **Noise is one line.** A host that accepts a connection on 200 ports is `"19500-19699 tcpwrapped"`, not 200 entries.
- **Output is bounded.** On a huge scan, `--max-bytes` cuts the least important data first and counts every cut.
- **Details are one file away.** naabu's JSONL and nmap's XML are saved to one file, and its path is in `raw`. It holds the timestamps, CPEs, OS hints and the fingerprints of unidentified services, costs no tokens until the agent opens it, and replays with `--input`.

Against the engines' text output (`naabu -silent` and nmap's normal output), raijin-ports is **15.2×** smaller on the noisy run and **1.5×** smaller on the findings run, where most ports are different services and both outputs list each one once. The text output also has no grouping, no ranking and no field names. Full method and numbers are in [BENCHMARK.md](BENCHMARK.md), and `bench/run.sh` reproduces them.

## Install

```bash
go install github.com/protonnegativo/raijin-ports/cmd/raijin-ports@latest
```

This installs the latest release. You also need `naabu` and `nmap` on `PATH`, or pass `--naabu <path>` and `--nmap <path>`. Without nmap, `--no-services` lists the open ports only.

**Versions.** Releases are tagged automatically on every change and every passing engine update. `raijin-ports --version` shows the release and the tested engine versions, e.g. `raijin-ports v0.1.3 (tested with naabu 2.6.1, nmap 7.98)`. `raijin-mcp update` updates every Raijin tool at once.

## Usage

```bash
raijin-ports --scope scope.txt                                       # scan every host the scope names
raijin-ports --scope scope.txt -host 10.0.0.0/24 -p 1-65535
raijin-ports --scope scope.txt -l hosts.txt --top-ports 1000 --max-items 20
raijin-ports --scope scope.txt -host app.example.com --no-services   # open ports only, no nmap
raijin-ports --scope scope.txt --input raw.txt                        # replay a saved run, nothing is sent
raijin-ports --scope scope.txt --input naabu.jsonl --input nmap.xml
raijin-ports --scope scope.txt -l hosts.txt --state run.json          # mark findings that are new since last run
raijin-ports ... --nmap-args "--version-intensity 9"                  # extra nmap arguments
raijin-ports ... -- -ec -retries 1                                    # anything after -- goes to naabu
```

`--scope` is required. One rule per line:

```
example.com
*.example.com
10.0.0.0/24
!10.0.0.13
```

Targets outside the scope are dropped before naabu runs. A CIDR target is expanded (up to a /16) and every address is checked on its own, so an exclusion inside a range is never scanned. Results for hosts outside the scope are dropped too. Both are counted in `omitted.out_of_scope`.

With no `-host`, `-l` or `--input`, raijin-ports scans what the scope names: every domain, every IP, and every address of ranges up to a /16, minus exclusions. A wildcard names no host and a larger range is too big to sweep at once, so for each one `next` gives the command to run first (`raijin-subs` for a wildcard, `-host` with the range split into /16s for a larger range).

`--input` reads naabu JSONL, naabu's text output (`host:port` per line), nmap XML (`-oX`), or a file with all of them, like the `raw` file. A replay never runs an engine: services are checked when the input has nmap output, and otherwise every port is listed with a guess from its number.

**Active scan.** naabu connects to every port it scans (a TCP connect scan, `-s c`, by default), and nmap sends service probes to the open ones. Scan only what you are authorized to test.

## Output

```json
{
  "schema_version": 1,
  "tool": "raijin-ports",
  "version": "0.1.0",
  "target": "bench/fixtures/findings/raw.txt",
  "summary": "6 hosts, 16 open ports, 9 findings (5 high, 3 medium, 1 low), 1 groups",
  "findings": [
    {
      "id": "datastore-4a8fe977",
      "title": "Exposed datastore: Redis key-value store",
      "severity": "high",
      "tags": ["datastore"],
      "service": "redis",
      "product": "Redis key-value store",
      "locations": ["127.0.0.2:19379", "127.0.0.5:19379"]
    },
    {
      "id": "admin-api-dc33a180",
      "title": "Exposed admin API: Docker remote API",
      "severity": "high",
      "tags": ["admin-api"],
      "service": "docker",
      "product": "Docker remote API",
      "version": "24.0.5",
      "info": "API 1.43",
      "locations": ["127.0.0.4:19375"]
    },
    {
      "id": "datastore-e01469ff",
      "title": "Exposed datastore: Elasticsearch REST API",
      "severity": "high",
      "tags": ["datastore"],
      "service": "http",
      "product": "Elasticsearch REST API",
      "version": "7.17.9",
      "info": "name: node-1; cluster: elasticsearch; Lucene 8.11.1",
      "locations": ["127.0.0.4:19920"]
    },
    {
      "id": "remote-admin-680eb916",
      "title": "SSH on a non-standard port",
      "severity": "medium",
      "tags": ["remote-admin"],
      "service": "ssh",
      "product": "OpenSSH",
      "version": "8.9p1 Ubuntu 3ubuntu0.4",
      "info": "Ubuntu Linux; protocol 2.0",
      "locations": ["127.0.0.2:19022", "127.0.0.5:19022"]
    },
    {
      "id": "outlier-3bab0b7a",
      "title": "Port open on one host only: Apache httpd",
      "severity": "low",
      "confidence": "heuristic",
      "tags": ["outlier"],
      "service": "http",
      "product": "Apache httpd",
      "version": "2.4.52",
      "info": "(Ubuntu)",
      "locations": ["127.0.0.7:19888"]
    }
  ],
  "groups": [
    {
      "id": "web-9479e041",
      "ports": ["19080 http nginx 1.18.0 (Ubuntu)"],
      "locations": ["127.0.0.2", "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7"]
    }
  ],
  "omitted": {"duplicates": 16}
}
```

That is the real findings run from the benchmark (`--input` on the saved naabu and nmap output of the local lab), pretty-printed here with short arrays kept on one line. One thing is shortened: 4 of the 9 findings (Memcached, MySQL, VNC, Telnet) are left out. The tool writes it as one line. `omitted.duplicates` is 16 because naabu's JSON output writes every port twice.

**Nothing the engines found is dropped silently.** Every open port is in exactly one finding or one group per service nmap reported on it. Only exact repeats collapse, and they are counted in `omitted.duplicates`.

What the reducer does:

- **One result per open port**: naabu's host, IP, port and protocol. The same port reached as `localhost` and as `127.0.0.1` is two results. nmap's answer is joined by IP, port and protocol, so a name gets the service nmap found on its address. A port nmap reports open that naabu did not (an nmap file of your own, read with `--input`) is a result too.
- **The service** is nmap's: `service` (`ssl/` first when nmap found TLS in front of it), `product`, `version` and `info` (nmap's extra information). A name with a trailing `?` is a guess from the port number (`6379` is `redis?`), written when nmap did not run, could not identify the service (`unknown`, `tcpwrapped`), or named it from its port table. When nmap sees a port closed or filtered that naabu found open, its state is kept (`8080 http-proxy? (nmap: closed)`, `"state": "closed"`).
- **Findings** are the ports that match a rule. Each rule has a fixed severity:

  | Tag | Severity | Rule |
  |---|---|---|
  | `datastore` | high | A database, cache, search engine or queue: MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, OpenSearch, Memcached, MSSQL, Oracle, Cassandra, CouchDB, ClickHouse, InfluxDB, Kafka, ZooKeeper, RabbitMQ, MQTT and others. |
  | `admin-api` | high | An API or console that controls infrastructure or runs code: the Docker API, Kubernetes and the kubelet, etcd, Jenkins, Consul, Nomad, Portainer, Jupyter, Kibana, JDWP, Java RMI and others. |
  | `remote-admin` | medium | RDP, VNC, Telnet, SMB, WinRM, X11, rlogin, rsh, rexec, and SSH on any port but 22. |
  | `file-share` | medium | FTP, TFTP, NFS, rpcbind, rsync, AFP. |
  | `outlier` | low, `heuristic` | Only one host has the port open, in a run of at least 4 hosts where one port is open on at least half of them. Not for a port nmap saw closed or `tcpwrapped`, or on a host with 32 open ports or more (a firewall or tarpit that answers on every port). |

  A rule matches nmap's service name or a word in nmap's product (`Elasticsearch REST API` is a datastore even though its service is `http`). When nmap did not identify the service, the port's well-known service decides and the finding is `heuristic`. A port matches one rule at most. Ports with the same service (the same name, product, version and info) and the same tag are one finding that lists every `host:port`.
- **Groups** are the ports that match no rule. Each host's other ports are its port set, and hosts with exactly the same set share one group that lists every host. A port is one string: the port (`/udp` for UDP), then the service, product, version and info as nmap's text output writes them: `"443 ssl/http nginx 1.18.0 (Ubuntu)"`. Neighbouring ports with the same description are one range: `"19080-19081 http nginx 1.18.0 (Ubuntu)"`, `"19500-19699 tcpwrapped"`. A host whose every port is a finding has no group.
- **Locations** are `ip:port` in findings and `ip` in groups, or `name:port [ip]` and `name [ip]` when the host is a name. IPv6 addresses are in brackets in findings (`[2001:db8::5]:2375`). Locations are sorted by IP, numerically.
- **Ranking:** findings by severity, then confidence (matched before heuristic), then the number of locations, then `id`. Groups by the number of hosts, then `id`. The same input always gives the same order.
- **`id`** is the tag (`web` or `ports` for a group, `web` when every port is HTTP) and a short hash of the service or port set, so the same service has the same `id` in the next run.
- **`raw`** is naabu's JSONL and nmap's XML, saved to one file. It holds the timestamps, CPEs, OS hints, the reason for each port state and nmap's fingerprints of services it could not identify; reading it costs no tokens until the agent opens it, and `--input` replays it. `--raw <file>` picks the path.
- **Budget:** `--max-bytes` (32,000 by default, about 400 hosts with a few ports each) keeps the output bounded on huge scans. It cuts in this order until the JSON fits:
  1. group hosts (the ports stay);
  2. groups;
  3. the locations of the lowest-ranked findings, each keeping one location plus its `count`;
  4. the lowest-ranked findings.

  Every cut is counted in `omitted`, `budget.truncated` is set, and `next` points to the raw file. `--max-items` caps the number of findings (0, the default, keeps all).
- **`schema_version`** is the first field of every result (currently `1`); it changes only when the shape of the JSON does.
- **Exit codes:** 0 is ok. 2 is a structured error with the JSON result on stdout: an invalid scope file (`errors` has one `kind:"scope"` entry per invalid line, as `line N: ...`, and nothing is scanned) or a missing engine (`kind:"missing_engine"`). 1 is wrong usage (bad flag, missing argument) and prints to stderr.
- **Errors** say what to try next. If naabu is missing, nothing runs and the exit code is 2. If nmap is missing, every port is still listed with a guessed service, the hint is in `errors`, and the exit code is 2.

Fields an agent can rebuild are left out to save tokens:

- `protocol` is left out for TCP, `state` for open; `product`, `version` and `info` when nmap had none.
- `count` appears only when the budget cut `locations`.
- `confidence` appears only when it is not `matched`.
- `omitted`, `errors` and `next` appear only when they are not empty.
- `budget` appears only when something was cut.

The JSON is compact (one line) by default because indentation costs 37% to 47% more tokens in the benchmark; `--pretty` indents it. `--format table` prints a short human view of the same result; it lists finding locations but only counts group hosts.

The Raijin banner is **off by default**, so normal runs stay small. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--scope` | (required) | scope file |
| `-host` / `-l` / `--input` | every host the scope names | hosts, IPs or CIDRs, comma-separated (repeatable) / target file / existing naabu and nmap output (repeatable) |
| `-p`, `--top-ports` | naabu's top 100 | naabu `-p` / `-tp` |
| `--rate`, `--threads`, `--timeout` | | naabu `-rate` / `-c` / `-timeout` (milliseconds) |
| `--no-services` | false | only find open ports; do not run nmap |
| `--nmap-args` | | extra nmap arguments, space-separated |
| `--max-items` | 0 | max findings (0 keeps all) |
| `--max-bytes` | 32000 | max JSON size; cuts are counted in `omitted` |
| `--raw` | temp file | where to save naabu's JSONL and nmap's XML |
| `--state` | | state file for new-since-last-run |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--naabu`, `--nmap` | naabu, nmap | paths to the binaries |
| `--banner` | false | print the banner to stderr |

## Engine versions

The tested versions of naabu and nmap are in `engines.json`, which is built into the binary. Before a scan, raijin-ports runs `naabu -version` and `nmap --version`; when the installed engine is another major version or older than the tested one, it says so in `errors` (`engine_version`) with the command to install the tested version. When an engine's output has results without the fields raijin-ports needs, it adds an `engine_format` error and counts them in `omitted.unparsed`. Neither stops the scan or changes the exit code. A weekly job runs the live benchmark with the latest naabu and nmap; when it passes with a newer version it commits the bump and tags a release, and when it breaks it opens an issue.

## Development

```bash
go test ./...
go vet ./...
```

The only Go dependency is [raijin-core](https://github.com/protonnegativo/raijin-core) (scope, schema envelope, state); everything else is the standard library. naabu runs as a subprocess with `-s c -json -silent -nc -duc -no-stdin`, and nmap with `-sT -sV -Pn -n -oX -` on the open ports only (`-sU` too for UDP ports, `-6` for IPv6), so the binary stays small and the engines can be updated on their own. IPs with the same open ports share one nmap run. The CLI tests run the live path offline with small fake engines; `testdata/sample.raw` is a synthetic run that hits every rule. `bench/lab.py` is the local lab of the benchmark: fake Redis, MySQL, Memcached, Elasticsearch, Docker API, SSH, VNC, Telnet and web servers on loopback addresses, each answering just enough for nmap to fingerprint it.

## Responsible use

Only scan hosts you are authorized to test. raijin-ports sends packets to every target: the scope is required and is checked before anything is sent.

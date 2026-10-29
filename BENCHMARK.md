# Token benchmark: naabu + nmap vs raijin-ports

How many tokens does an AI agent spend reading the result of a port scan with service detection, and does it lose anything? This benchmark scans a local lab with naabu, identifies every open port with nmap, counts the tokens in each output shape, and checks that every port and service is in the raijin-ports output.

Reproduce from the saved engine output: `bench/run.sh`. Start the lab, rescan it and refresh the fixtures first: `LIVE=1 bench/run.sh` (needs naabu and nmap; timestamps and latencies will differ, the ports and services should not).

## Setup

- **Lab:** `bench/lab.py`, one python process with fake services on loopback addresses (127.0.0.0/8), ports 19000 to 19999, started by `bench/run.sh` and stopped when it exits. Each service answers just enough for nmap `-sV` to fingerprint it: nginx and Apache web servers, an OpenSSH banner, Redis, MySQL, Memcached, Elasticsearch, the Docker remote API, VNC, Telnet, and a "closer" that accepts a connection and closes it at once, like a firewall or tarpit (nmap: `tcpwrapped`). Nothing outside the machine was scanned. The run was on 2026-10-24.
- **naabu:** v2.6.1, `-p 19000-19999 -s c -rate 500` (a TCP connect scan at 500 packets per second). **nmap:** 7.94SVN, `-sT -sV -Pn -n` on the open ports only, one run per set of IPs with the same open ports, as raijin-ports runs it.
- **Fixtures:** `bench/fixtures/<scenario>/raw.txt` is the `raw` file of the live raijin-ports run: naabu's `-json` lines, then nmap's `-oX` documents. `naabu.txt` is naabu's text output (`-silent`) on the same targets and ports, and `nmap.txt` is nmap's normal output on the same ports, both run right after. Every row below is computed from these files, so `bench/run.sh` gives the same numbers offline.
- **raijin-ports:** replays `raw.txt` with `--input`, so every row sees the same ports and services. Defaults apply: no limit on findings, and `--max-bytes 32000`, which was not reached.
- **Baselines**, as an agent would read the engines:
  - JSON: `raw.txt` itself, naabu `-json` plus nmap `-oX` (nmap has no JSON output; XML is its structured one). naabu 2.6.1 writes every port twice in `-json` mode (once when it finds it, once at the end), so its JSON has twice the lines of its text output; raijin-ports counts the repeats in `omitted.duplicates`.
  - Text: `naabu -silent` (one `host:port` per line), then nmap's normal output, with its header and footer lines.
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.

## Scenario 1: noisy

27 hosts, 249 open ports. localhost and 21 other hosts have the same two nginx ports, 4 have one Apache port, one of the 22 also has an Apache port no other host has, and one accepts a connection on 200 ports. raijin-ports returned 1 finding (the one-off Apache port, low, heuristic) and 3 groups: the 22 nginx hosts, the 4 Apache hosts, and `19500-19699 tcpwrapped`.

| Output | Bytes | Tokens | vs. engines JSON |
|---|---:|---:|---:|
| naabu `-json` + nmap `-oX` | 110,550 | 41,933 | 1× |
| naabu text + nmap text | 16,685 | 6,981 | 6.0× |
| **raijin-ports JSON (default)** | 1,100 | **459** | **91×** |
| raijin-ports `--pretty` | 1,684 | 630 | 67× |
| raijin-ports `--format table` | 304 | 108 | 388× |

## Scenario 2: findings

6 hosts, 16 open ports. raijin-ports returned 9 findings and 1 group:

- high: Redis (2 hosts), the Docker remote API, Memcached, MySQL, Elasticsearch;
- medium: SSH on port 19022 (2 hosts), VNC, Telnet;
- low: an Apache port only one host has open (heuristic);
- the group: nginx on 19080, on 5 hosts.

| Output | Bytes | Tokens | vs. engines JSON |
|---|---:|---:|---:|
| naabu `-json` + nmap `-oX` | 13,383 | 5,151 | 1× |
| naabu text + nmap text | 3,184 | 1,175 | 4.4× |
| **raijin-ports JSON (default)** | 2,418 | **780** | **6.6×** |
| raijin-ports `--pretty` | 3,556 | 1,150 | 4.5× |
| raijin-ports `--format table` | 900 | 315 | 16× |

In both scenarios the raijin-ports JSON includes about 10 tokens for `target`, the path of the replayed fixture. A live run writes the targets there and adds about 18 tokens for `raw`.

**Not in the lab:** UDP ports, IPv6, names that resolve to other addresses, FTP, RDP, guessed services (nmap missing) and nmap seeing a port closed. They are covered by the synthetic fixture `testdata/sample.raw` and the unit tests, not by this benchmark.

## Nothing is lost

For each scenario, `bench/verify.py` checks the engines' output (`raw.txt`) against the raijin-ports output. A result is:

- each open port naabu reported, identified by (host, IP, port, protocol): it must be in the `locations` of a finding with the same protocol, or in a group that lists the host and has the port in its `ports` (ranges expanded);
- each port nmap reported open with a service, identified by (IP, port, service): every naabu host on that IP must have the port with the same service name, and the same product and version.

Results:

- Scenario 1: 249 naabu results, 249 nmap services, **0 missing**.
- Scenario 2: 16 naabu results, 16 nmap services, **0 missing**.

`verify.py` fails when a location is removed or a version is changed in the output (checked by hand on scenario 2: 7 missing).

What the JSON leaves out stays in `raw`, which raijin-ports saves to disk: timestamps, CPEs, OS hints, the reason for each port state, latencies, and nmap's fingerprints of services it could not identify.

## Reading the numbers

- **Against the engines' JSON and XML**, the structured output an agent would parse, raijin-ports uses **91×** fewer tokens on the noisy run and **6.6×** fewer on the findings run. nmap's XML repeats the state, the reason and the CPEs on every port, and the scan metadata on every run; naabu's JSON repeats its field names and a timestamp on every line, and writes every port twice.
- **Against the engines' text output**, the gap depends on the run:
  - noisy: **15.2× smaller** (6,981 → 459);
  - findings: **1.5× smaller** (1,175 → 780).

  When many hosts share the same ports, nmap's text repeats one block per host and raijin-ports writes the ports once with every host. When most ports are different services, both outputs list each one once, and raijin-ports pays for field names and titles; in exchange the agent gets the findings ranked, with a severity, and the hosts with the same services joined.
- **The output stays bounded.** On a scan too big for `--max-bytes`, raijin-ports cuts the least important data first: group hosts, then groups, then extra locations of low-ranked findings, then low-ranked findings. Every cut is counted in `omitted`, and `next` points to the raw file. The engines' output has no upper bound.

## How the default output got here

o200k tokens, on the same fixtures:

| Version | Scenario 1 | Scenario 2 | Lossless? |
|---|---:|---:|---|
| any port only one host has is an `outlier` | 2,662 | 768 | yes |
| **no outliers on `tcpwrapped`, closed, or hosts with 32+ open ports** (current) | **459** | **780** | **yes** |

In the first version the 200 ports of the closer were 200 outlier locations in one finding; they are noise from one host that answers on every port, and are now one group with one range.

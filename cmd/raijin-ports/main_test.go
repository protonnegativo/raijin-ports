package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scopeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("10.0.0.0/24\n*.example.com\n2001:db8::/64\n!10.0.0.200\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type output struct {
	Target   string
	Summary  string
	Findings []struct {
		ID, Severity, Service string
		Locations             []string
	}
	Groups []struct {
		ID        string
		Ports     []string
		Locations []string
	}
	Omitted map[string]int
	Errors  []struct{ Kind, Hint string }
	Raw     string
}

const sample = "../../testdata/sample.raw"

func TestNoBannerByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--input", sample}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty without --banner, got %q", errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--banner", "--scope", scopeFile(t), "--input", sample}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-ports v"+version) {
		t.Errorf("banner missing or without the version: %q", errb.String())
	}
	if strings.Contains(out.String(), "TGT-LOCK") {
		t.Error("banner leaked into stdout")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}

func TestCompactByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", sample}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	var pretty bytes.Buffer
	if code := run([]string{"--pretty", "--scope", scopeFile(t), "--input", sample}, &pretty, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(pretty.String(), "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty.String())
	}
	var a, b map[string]any
	if json.Unmarshal(out.Bytes(), &a) != nil || json.Unmarshal(pretty.Bytes(), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
	want := `"summary":"10 hosts, 28 open ports, 8 findings (3 high, 3 medium, 2 low), 4 groups"`
	if !strings.Contains(out.String(), want) {
		t.Errorf("summary: %s", out.String())
	}
	if !strings.Contains(out.String(), `"omitted":{"duplicates":1,"out_of_scope":1}`) {
		t.Errorf("omitted: %s", out.String())
	}
}

func TestInputCanBeSplitAcrossFiles(t *testing.T) {
	b, err := os.ReadFile(sample)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	i := strings.Index(string(b), "<?xml")
	os.WriteFile(filepath.Join(dir, "naabu.jsonl"), b[:i], 0o600)
	os.WriteFile(filepath.Join(dir, "nmap.xml"), b[i:], 0o600)
	var whole, split, errb bytes.Buffer
	run([]string{"--scope", scopeFile(t), "--input", sample}, &whole, &errb)
	run([]string{"--scope", scopeFile(t), "--input", filepath.Join(dir, "naabu.jsonl"), "--input", filepath.Join(dir, "nmap.xml")}, &split, &errb)
	var a, c output
	json.Unmarshal(whole.Bytes(), &a)
	json.Unmarshal(split.Bytes(), &c)
	if a.Summary != c.Summary || len(a.Findings) != len(c.Findings) || len(a.Groups) != len(c.Groups) {
		t.Errorf("one combined file and two files should give the same result:\n%s\n%s", whole.String(), split.String())
	}

	// naabu output alone: every port is listed, services are guesses from the port number
	var only bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", filepath.Join(dir, "naabu.jsonl")}, &only, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var o output
	json.Unmarshal(only.Bytes(), &o)
	if !strings.Contains(o.Summary, "28 open ports (services not checked)") || !strings.Contains(only.String(), `"80 http?`) {
		t.Errorf("naabu-only replay: %s", only.String())
	}
}

func TestMissingEngineExitsTwoWithHint(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-host", "10.0.0.1", "--naabu", "/nonexistent/naabu"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var v output
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || len(v.Errors) != 1 || v.Errors[0].Kind != "missing_engine" || !strings.Contains(v.Errors[0].Hint, "--naabu") {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestUsageErrorsExitOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--input", sample}, &out, &errb); code != 1 {
		t.Errorf("no --scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-host", "192.0.2.1"}, &out, &errb); code != 1 {
		t.Errorf("no target in scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-host", "10.0.0.0/8"}, &out, &errb); code != 1 {
		t.Errorf("a range too large: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "--nope"}, &out, &errb); code != 1 {
		t.Errorf("unknown flag: exit %d, want 1", code)
	}
}

// fakeEngines writes shell scripts that answer like naabu and nmap, so the live path runs offline. The
// fake naabu says ports 80 and 6379 are open on every target and writes each line twice, as naabu
// -json does; it fails if it is asked to scan an excluded address. The fake nmap names the services.
// Both answer their version command with the tested version.
func fakeEngines(t *testing.T) (string, string, string) {
	return fakeEnginesAt(t, "2.6.1", "7.94SVN", `{\"ip\":\"$h\",\"port\":80,\"protocol\":\"tcp\",\"tls\":false}`)
}

// fakeEnginesAt is fakeEngines with the given versions and naabu's line for port 80 of an IP target.
func fakeEnginesAt(t *testing.T, naabuVersion, nmapVersion, line80 string) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "targets.log")
	nb := `#!/bin/sh
[ "$1" = -version ] && { echo "[INF] Current Version: ` + naabuVersion + `" >&2; exit 0; }
while [ "$1" != "-l" ]; do shift; done
cp "$2" "` + log + `"
for pass in 1 2; do
while read -r h; do
  case "$h" in
    10.0.0.200) echo "excluded address sent to naabu" >&2; exit 1 ;;
    *.*.*.*) echo "` + line80 + `"; echo "{\"ip\":\"$h\",\"port\":6379,\"protocol\":\"tcp\",\"tls\":false}" ;;
    *) echo "{\"host\":\"$h\",\"ip\":\"10.0.0.50\",\"port\":80,\"protocol\":\"tcp\",\"tls\":false}" ;;
  esac
done < "$2"
done
`
	nm := `#!/bin/sh
[ "$1" = --version ] && { echo "Nmap version ` + nmapVersion + ` ( https://nmap.org )"; exit 0; }
ips=""
for a in "$@"; do case "$a" in *.*.*.*) ips="$ips $a" ;; esac; done
echo '<?xml version="1.0" encoding="UTF-8"?>'
echo '<nmaprun scanner="nmap" args="nmap '"$*"'">'
for ip in $ips; do
  echo "<host><address addr=\"$ip\" addrtype=\"ipv4\"/><ports>"
  echo '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0" method="probed" conf="10"/></port>'
  case "$*" in *6379*) echo '<port protocol="tcp" portid="6379"><state state="open"/><service name="redis" product="Redis key-value store" method="probed" conf="10"/></port>' ;; esac
  echo "</ports></host>"
done
echo '</nmaprun>'
`
	for name, body := range map[string]string{"naabu": nb, "nmap": nm} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "naabu"), filepath.Join(dir, "nmap"), log
}

func TestLiveRunAndReplay(t *testing.T) {
	nb, nm, log := fakeEngines(t)
	raw := filepath.Join(t.TempDir(), "raw.txt")
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-host", "10.0.0.198/30,www.example.com", "-host", "192.0.2.1", "--naabu", nb, "--nmap", nm, "--raw", raw}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	var v output
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Errors) != 0 || v.Raw != raw {
		t.Fatalf("errors or raw: %s", out.String())
	}
	// 10.0.0.196/30 is 196-199 (scanned) and 10.0.0.200 is not in it; the exclusion is tested below
	targets, _ := os.ReadFile(log)
	if string(targets) != "10.0.0.196\n10.0.0.197\n10.0.0.198\n10.0.0.199\nwww.example.com\n" {
		t.Errorf("naabu targets: %q", targets)
	}
	want := "5 hosts, 9 open ports, 1 findings (1 high), 1 groups"
	if v.Summary != want || v.Omitted["duplicates"] != 9 || v.Omitted["out_of_scope"] != 1 {
		t.Errorf("summary %q omitted %v, want %q", v.Summary, v.Omitted, want)
	}
	if len(v.Findings) != 1 || v.Findings[0].Service != "redis" || len(v.Findings[0].Locations) != 4 {
		t.Errorf("findings: %s", out.String())
	}
	b, _ := os.ReadFile(raw)
	if !strings.Contains(string(b), `"port":6379`) || !strings.Contains(string(b), "<nmaprun") {
		t.Errorf("raw should hold both engines' output: %s", b)
	}

	// replaying the raw file gives the same result without running anything
	var again bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", raw, "--naabu", "/nonexistent", "--nmap", "/nonexistent"}, &again, &errb); code != 0 {
		t.Fatalf("replay exit %d", code)
	}
	var r output
	json.Unmarshal(again.Bytes(), &r)
	if r.Summary != v.Summary {
		t.Errorf("replay summary %q, want %q", r.Summary, v.Summary)
	}
}

func TestExcludedAddressInARangeIsNeverScanned(t *testing.T) {
	nb, nm, log := fakeEngines(t)
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-host", "10.0.0.200/31", "--naabu", nb, "--nmap", nm, "--raw", filepath.Join(t.TempDir(), "raw.txt")}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	targets, _ := os.ReadFile(log)
	if string(targets) != "10.0.0.201\n" {
		t.Errorf("naabu targets: %q", targets)
	}
}

func TestMissingNmapStillListsEveryPort(t *testing.T) {
	nb, _, _ := fakeEngines(t)
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-host", "10.0.0.1", "--naabu", nb, "--nmap", "/nonexistent/nmap", "--raw", filepath.Join(t.TempDir(), "raw.txt")}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var v output
	json.Unmarshal(out.Bytes(), &v)
	if len(v.Errors) != 1 || !strings.Contains(v.Errors[0].Hint, "--nmap") || !strings.Contains(v.Summary, "services not checked") {
		t.Errorf("stdout = %s", out.String())
	}
	if len(v.Findings) != 1 || v.Findings[0].Service != "redis?" || len(v.Groups) != 1 || v.Groups[0].Ports[0] != "80 http?" {
		t.Errorf("ports should be listed with guessed services: %s", out.String())
	}
}

func TestNoServicesDoesNotRunNmap(t *testing.T) {
	nb, _, _ := fakeEngines(t)
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-host", "10.0.0.1", "--no-services", "--naabu", nb, "--nmap", "/nonexistent/nmap", "--raw", filepath.Join(t.TempDir(), "raw.txt")}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	var v output
	json.Unmarshal(out.Bytes(), &v)
	if len(v.Errors) != 0 || v.Summary != "1 hosts, 2 open ports (services not checked), 1 findings (1 high), 1 groups" {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestTableFormat(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", sample, "--format", "table"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	s := out.String()
	for _, want := range []string{
		"HIGH     admin-api Exposed admin API: Docker remote API (1)", "         [2001:db8::5]:2375",
		"group    9000-9004 tcpwrapped (1 host)", "(4 hosts)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("table missing %q:\n%s", want, s)
		}
	}
}

// With only --scope, every host the scope names is scanned and wildcards and large ranges get a next step.
func TestScopeAloneScansWhatTheScopeNames(t *testing.T) {
	nb, nm, log := fakeEngines(t)
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("example.com\n*.example.com\n10.0.0.200/30\n!10.0.0.200\n10.0.0.0/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopePath, "--naabu", nb, "--nmap", nm, "--raw", filepath.Join(dir, "raw.txt")}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	targets, _ := os.ReadFile(log)
	if string(targets) != "example.com\n10.0.0.201\n10.0.0.202\n10.0.0.203\n" {
		t.Errorf("naabu targets: %q", targets)
	}
	var res struct {
		Next    []string
		Omitted map[string]int
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Next) != 2 || !strings.Contains(res.Next[0], "raijin-subs --scope "+scopePath+" -d example.com") || !strings.Contains(res.Next[1], "-host <range> to cover 10.0.0.0/8") {
		t.Errorf("next = %v", res.Next)
	}
	if res.Omitted["out_of_scope"] != 0 {
		t.Errorf("the scope's own exclusions are not out-of-scope targets: %v", res.Omitted)
	}
}

func TestUntestedEngineVersionWarnsWithoutChangingTheRun(t *testing.T) {
	nb, nm, _ := fakeEnginesAt(t, "2.5.0", "7.95", `{\"ip\":\"$h\",\"port\":80,\"protocol\":\"tcp\",\"tls\":false}`)
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-host", "10.0.0.5", "--naabu", nb, "--nmap", nm, "--raw", filepath.Join(t.TempDir(), "raw")}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var v output
	json.Unmarshal(out.Bytes(), &v)
	// naabu 2.5.0 is older than tested; nmap 7.95 is a newer minor of the same major, which is silent
	if len(v.Errors) != 1 || v.Errors[0].Kind != "engine_version" || !strings.HasPrefix(v.Errors[0].Hint, "naabu 2.5.0 is not the tested 2.6.1") {
		t.Fatalf("errors: %s", out.String())
	}
	if v.Summary != "1 hosts, 2 open ports, 1 findings (1 high), 1 groups" {
		t.Errorf("summary %q", v.Summary)
	}
}

func TestRenamedFieldIsAnEngineFormatError(t *testing.T) {
	// naabu renamed "port" to "p" on port 80 lines: those results are counted, not dropped silently
	nb, nm, _ := fakeEnginesAt(t, "2.6.1", "7.94SVN", `{\"ip\":\"$h\",\"p\":80,\"protocol\":\"tcp\",\"tls\":false}`)
	raw := filepath.Join(t.TempDir(), "raw")
	var out, errb bytes.Buffer
	run([]string{"--scope", scopeFile(t), "-host", "10.0.0.5", "--naabu", nb, "--nmap", nm, "--raw", raw}, &out, &errb)
	var v output
	json.Unmarshal(out.Bytes(), &v)
	if len(v.Errors) != 1 || v.Errors[0].Kind != "engine_format" || v.Errors[0].Hint != "2 of 4 naabu results had no ip or host, and port; the engine's output format may have changed. Read "+raw+" for the full output" {
		t.Fatalf("errors: %s", out.String())
	}
	if v.Omitted["unparsed"] != 2 {
		t.Errorf("omitted %v", v.Omitted)
	}

	// nmap renamed portid: its ports are counted the same way, in a replay too
	in := filepath.Join(t.TempDir(), "in.xml")
	os.WriteFile(in, []byte(`<nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/><ports><port protocol="tcp" port="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>
`), 0o600)
	out.Reset()
	run([]string{"--scope", scopeFile(t), "--input", in}, &out, &errb)
	v = output{}
	json.Unmarshal(out.Bytes(), &v)
	if len(v.Errors) != 1 || v.Errors[0].Kind != "engine_format" || !strings.HasPrefix(v.Errors[0].Hint, "1 of 1 nmap results had no address, portid and state") || v.Omitted["unparsed"] != 1 {
		t.Fatalf("nmap: %s", out.String())
	}
}

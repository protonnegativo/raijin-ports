package reduce

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-ports/internal/naabu"
	"github.com/protonnegativo/raijin-ports/internal/nmap"
	"github.com/protonnegativo/raijin-ports/internal/schema"
	"github.com/protonnegativo/raijin-ports/internal/scope"
)

func n(host, ip string, port int) naabu.Result {
	return naabu.Result{Host: host, IP: ip, Port: port, Protocol: "tcp"}
}

func svc(ip string, port int, name, product, version string) nmap.Port {
	return nmap.Port{IP: ip, Port: port, Protocol: "tcp", State: "open", Service: name, Product: product, Version: version}
}

// locations returns every location of every finding and every host:port of every group (ranges expanded
// only for single ports), to check that nothing was lost.
func has(out Output, loc string) bool {
	for _, f := range out.Findings {
		for _, l := range f.Locations {
			if l == loc {
				return true
			}
		}
	}
	host, port, _ := strings.Cut(loc, ":")
	for _, g := range out.Groups {
		for _, l := range g.Locations {
			if l != host {
				continue
			}
			for _, p := range g.Ports {
				if strings.SplitN(p, " ", 2)[0] == port {
					return true
				}
			}
		}
	}
	return false
}

func TestEveryOpenPortIsListedOnce(t *testing.T) {
	results := []naabu.Result{n("", "10.0.0.1", 80), n("", "10.0.0.1", 6379), n("", "10.0.0.2", 80), n("", "10.0.0.2", 22)}
	ports := []nmap.Port{
		svc("10.0.0.1", 80, "http", "nginx", "1.18.0"), svc("10.0.0.1", 6379, "redis", "Redis key-value store", "7.0.11"),
		svc("10.0.0.2", 80, "http", "nginx", "1.18.0"), svc("10.0.0.2", 22, "ssh", "OpenSSH", "8.9p1"),
	}
	out := Reduce(results, ports, Defaults())
	for _, loc := range []string{"10.0.0.1:80", "10.0.0.1:6379", "10.0.0.2:80", "10.0.0.2:22"} {
		if !has(out, loc) {
			t.Errorf("%s is missing: %+v", loc, out)
		}
	}
	if out.Hosts != 2 || out.Ports != 4 {
		t.Errorf("hosts %d ports %d", out.Hosts, out.Ports)
	}
	if len(out.Findings) != 1 || out.Findings[0].Service.Service != "redis" || out.Findings[0].Version != "7.0.11" || out.Findings[0].Severity != "high" {
		t.Errorf("redis should be the only finding: %+v", out.Findings)
	}
	// SSH on 22 is expected: it stays in the group, which is not shared with the host that has only 80
	if len(out.Groups) != 2 {
		t.Errorf("groups: %+v", out.Groups)
	}
}

func TestExactDuplicatesCollapseAndAreCounted(t *testing.T) {
	results := []naabu.Result{n("", "10.0.0.1", 80), n("", "10.0.0.1", 80), n("", "10.0.0.1", 80)}
	out := Reduce(results, nil, Defaults())
	if out.Omitted["duplicates"] != 2 || out.Ports != 1 {
		t.Errorf("omitted %v ports %d", out.Omitted, out.Ports)
	}
}

func TestNameAndIPAreDifferentHosts(t *testing.T) {
	// the same port reached as localhost and as 127.0.0.1 is two results, not a duplicate
	results := []naabu.Result{n("localhost", "127.0.0.1", 80), n("", "127.0.0.1", 80), n("127.0.0.1", "127.0.0.1", 80)}
	out := Reduce(results, []nmap.Port{svc("127.0.0.1", 80, "http", "nginx", "")}, Defaults())
	if out.Ports != 2 || out.Omitted["duplicates"] != 1 {
		t.Fatalf("ports %d omitted %v", out.Ports, out.Omitted)
	}
	if len(out.Groups) != 1 || strings.Join(out.Groups[0].Locations, ",") != "127.0.0.1,localhost [127.0.0.1]" {
		t.Errorf("groups: %+v", out.Groups)
	}
	if out.Groups[0].Ports[0] != "80 http nginx" {
		t.Errorf("nmap's service is joined by IP to the name too: %v", out.Groups[0].Ports)
	}
}

func TestHostsWithTheSamePortsShareAGroup(t *testing.T) {
	var results []naabu.Result
	var ports []nmap.Port
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		results = append(results, n("", ip, 80), n("", ip, 443))
		ports = append(ports, svc(ip, 80, "http", "nginx", "1.18.0"), svc(ip, 443, "ssl/http", "nginx", "1.18.0"))
	}
	// same ports, other version: another group, the version is not lost
	results = append(results, n("", "10.0.0.4", 80), n("", "10.0.0.4", 443))
	ports = append(ports, svc("10.0.0.4", 80, "http", "nginx", "1.25.3"), svc("10.0.0.4", 443, "ssl/http", "nginx", "1.25.3"))
	out := Reduce(results, ports, Defaults())
	if len(out.Groups) != 2 || len(out.Groups[0].Locations) != 3 || !strings.HasPrefix(out.Groups[0].ID, "web-") {
		t.Fatalf("groups: %+v", out.Groups)
	}
	if strings.Join(out.Groups[1].Ports, "|") != "80 http nginx 1.25.3|443 ssl/http nginx 1.25.3" {
		t.Errorf("ports: %v", out.Groups[1].Ports)
	}
}

func TestSameServiceAcrossHostsIsOneFinding(t *testing.T) {
	results := []naabu.Result{n("", "10.0.0.1", 6379), n("db.example.com", "10.0.0.2", 16379)}
	ports := []nmap.Port{svc("10.0.0.1", 6379, "redis", "Redis key-value store", ""), svc("10.0.0.2", 16379, "redis", "Redis key-value store", "")}
	out := Reduce(results, ports, Defaults())
	if len(out.Findings) != 1 || strings.Join(out.Findings[0].Locations, ",") != "10.0.0.1:6379,db.example.com:16379 [10.0.0.2]" {
		t.Errorf("findings: %+v", out.Findings)
	}
	if len(out.Groups) != 0 {
		t.Errorf("a host whose every port is a finding has no group: %+v", out.Groups)
	}
}

func TestRules(t *testing.T) {
	tests := []struct {
		port            int
		name, product   string
		tag, sev, title string
		heuristic       bool
	}{
		{3306, "mysql", "MySQL", "datastore", "high", "Exposed datastore: MySQL", false},
		{9200, "http", "Elasticsearch REST API", "datastore", "high", "Exposed datastore: Elasticsearch REST API", false},
		{2375, "docker", "Docker remote API", "admin-api", "high", "Exposed admin API: Docker remote API", false},
		{8080, "http", "Jetty", "", "", "", false},
		{8080, "http", "Jenkins", "admin-api", "high", "Exposed admin API: Jenkins", false},
		{22, "ssh", "OpenSSH", "", "", "", false},
		{2222, "ssh", "OpenSSH", "remote-admin", "medium", "SSH on a non-standard port", false},
		{3389, "ms-wbt-server", "", "remote-admin", "medium", "Remote admin: ms-wbt-server", false},
		{445, "microsoft-ds", "", "remote-admin", "medium", "Remote admin: microsoft-ds", false},
		{21, "ftp", "vsftpd", "file-share", "medium", "File share: vsftpd", false},
		{6379, "", "", "datastore", "high", "Exposed datastore: redis?", true},           // no nmap: guessed from the port
		{27017, "unknown", "", "datastore", "high", "Exposed datastore: mongodb?", true}, // nmap could not tell
		{6379, "http", "nginx", "", "", "", false},                                       // nmap knows better than the port
	}
	for _, tt := range tests {
		ports := []nmap.Port{}
		if tt.name != "" {
			ports = append(ports, svc("10.0.0.1", tt.port, tt.name, tt.product, ""))
		}
		out := Reduce([]naabu.Result{n("", "10.0.0.1", tt.port)}, ports, Defaults())
		if tt.tag == "" {
			if len(out.Findings) != 0 || len(out.Groups) != 1 {
				t.Errorf("%d %s: want a group, got %+v", tt.port, tt.name, out)
			}
			continue
		}
		if len(out.Findings) != 1 {
			t.Errorf("%d %s: want a finding, got %+v", tt.port, tt.name, out)
			continue
		}
		f := out.Findings[0]
		if f.Tags[0] != tt.tag || f.Severity != tt.sev || f.Title != tt.title || (f.Confidence == "heuristic") != tt.heuristic {
			t.Errorf("%d %s: got %s %s %q %q", tt.port, tt.name, f.Tags[0], f.Severity, f.Title, f.Confidence)
		}
		if !strings.HasPrefix(f.ID, tt.tag+"-") {
			t.Errorf("id %s", f.ID)
		}
	}
}

func TestGuessKeepsTLSAndMarksTheService(t *testing.T) {
	out := Reduce([]naabu.Result{{IP: "10.0.0.1", Port: 443, Protocol: "tcp", TLS: true}, n("", "10.0.0.1", 19000)}, nil, Defaults())
	if len(out.Groups) != 1 || strings.Join(out.Groups[0].Ports, "|") != "443 ssl/https?|19000" {
		t.Errorf("groups: %+v", out.Groups)
	}
}

func TestOutliers(t *testing.T) {
	var results []naabu.Result
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"} {
		results = append(results, n("", ip, 80))
	}
	results = append(results, n("", "10.0.0.4", 8081))
	out := Reduce(results, nil, Defaults())
	if len(out.Findings) != 1 || out.Findings[0].Tags[0] != "outlier" || out.Findings[0].Confidence != "heuristic" || out.Findings[0].Locations[0] != "10.0.0.4:8081" {
		t.Fatalf("findings: %+v", out.Findings)
	}
	if out.Findings[0].Title != "Port open on one host only: port 8081" || out.Findings[0].Severity != "low" {
		t.Errorf("title %q", out.Findings[0].Title)
	}

	// fewer hosts than OutlierMin: no baseline, no outliers
	if out := Reduce(results[2:], nil, Defaults()); len(out.Findings) != 0 {
		t.Errorf("3 hosts should have no outliers: %+v", out.Findings)
	}
	// no port that half the hosts share: no baseline
	spread := []naabu.Result{n("", "10.0.0.1", 1001), n("", "10.0.0.2", 1002), n("", "10.0.0.3", 1003), n("", "10.0.0.4", 1004)}
	if out := Reduce(spread, nil, Defaults()); len(out.Findings) != 0 {
		t.Errorf("no baseline should mean no outliers: %+v", out.Findings)
	}
	// a host that answers on every port is not an outlier 40 times over, and neither is tcpwrapped
	tarpit := append([]naabu.Result(nil), results[:4]...)
	var wrapped []nmap.Port
	for p := 9000; p < 9040; p++ {
		tarpit = append(tarpit, n("", "10.0.0.9", p))
	}
	tarpit = append(tarpit, n("", "10.0.0.8", 7000))
	wrapped = append(wrapped, svc("10.0.0.8", 7000, "tcpwrapped", "", ""))
	out = Reduce(tarpit, wrapped, Defaults())
	if len(out.Findings) != 0 {
		t.Errorf("tarpit and tcpwrapped ports are not outliers: %+v", out.Findings)
	}
}

func TestRangesAreLossless(t *testing.T) {
	got := Ranges([]string{"21 ftp", "22 tcpwrapped", "23 tcpwrapped", "24 tcpwrapped", "26 tcpwrapped", "27", "28", "53/udp domain", "54/udp domain"})
	want := "21 ftp|22-24 tcpwrapped|26 tcpwrapped|27-28|53-54/udp domain"
	if strings.Join(got, "|") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(got, "|"), want)
	}
}

func TestNmapStateAndUDPAreKept(t *testing.T) {
	results := []naabu.Result{n("", "10.0.0.1", 8080), {IP: "10.0.0.1", Port: 53, Protocol: "udp"}, n("", "10.0.0.1", 53)}
	ports := []nmap.Port{{IP: "10.0.0.1", Port: 8080, Protocol: "tcp", State: "closed", Service: "http-proxy", Guess: true},
		{IP: "10.0.0.1", Port: 53, Protocol: "udp", State: "open", Service: "domain", Product: "dnsmasq", Version: "2.86"}}
	out := Reduce(results, ports, Defaults())
	if out.Ports != 3 || len(out.Groups) != 1 {
		t.Fatalf("out: %+v", out)
	}
	if got := strings.Join(out.Groups[0].Ports, "|"); got != "53 domain?|8080 http-proxy? (nmap: closed)|53/udp domain dnsmasq 2.86" {
		t.Errorf("ports: %s", got)
	}
}

func TestNmapOnlyOpenPortsAreResults(t *testing.T) {
	ports := []nmap.Port{svc("10.0.0.1", 3306, "mysql", "MySQL", "8.0.33"), {IP: "10.0.0.1", Port: 25, Protocol: "tcp", State: "closed"}}
	out := Reduce(nil, ports, Defaults())
	if out.Ports != 1 || len(out.Findings) != 1 || out.Findings[0].Locations[0] != "10.0.0.1:3306" {
		t.Errorf("out: %+v", out)
	}
}

func TestOutOfScopeIsDroppedAndCounted(t *testing.T) {
	sc, _ := scope.Parse([]string{"10.0.0.0/24", "*.example.com", "2001:db8::/64", "!10.0.0.9"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	results := []naabu.Result{n("", "10.0.0.1", 80), n("", "10.0.0.9", 80), n("", "192.0.2.1", 80), n("www.example.com", "192.0.2.5", 80),
		n("evil.org", "10.0.0.2", 80), n("", "2001:db8::5", 22)}
	out := Reduce(results, nil, opt)
	if out.Omitted["out_of_scope"] != 3 || out.Ports != 3 {
		t.Errorf("omitted %v ports %d", out.Omitted, out.Ports)
	}
	found := false
	for _, g := range out.Groups {
		for _, l := range g.Locations {
			found = found || l == "www.example.com [192.0.2.5]"
		}
	}
	if !found {
		t.Errorf("a name in scope is kept whatever its IP: %+v", out.Groups)
	}
}

func TestIPv6Locations(t *testing.T) {
	out := Reduce([]naabu.Result{n("", "2001:db8::5", 2375)}, []nmap.Port{svc("2001:db8::5", 2375, "docker", "Docker remote API", "")}, Defaults())
	if len(out.Findings) != 1 || out.Findings[0].Locations[0] != "[2001:db8::5]:2375" {
		t.Errorf("findings: %+v", out.Findings)
	}
}

func TestOrderIsDeterministic(t *testing.T) {
	b, err := os.ReadFile("../../testdata/sample.raw")
	if err != nil {
		t.Fatal(err)
	}
	results, _ := naabu.Parse(strings.NewReader(string(b)))
	ports, _ := nmap.Parse(strings.NewReader(string(b)))
	first := Reduce(results, ports, Defaults())
	// the same input in reverse order gives the same output
	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}
	second := Reduce(results, ports, Defaults())
	a, _ := schema.Marshal([]any{first.Findings, first.Groups})
	c, _ := schema.Marshal([]any{second.Findings, second.Groups})
	if string(a) != string(c) {
		t.Errorf("order changed the output:\n%s\n%s", a, c)
	}
	sev := []string{}
	for _, f := range first.Findings {
		sev = append(sev, f.Severity)
	}
	if strings.Join(sev, ",") != "high,high,high,medium,medium,medium,low,low" {
		t.Errorf("ranking: %v", sev)
	}
}

func TestFitCountsEveryCut(t *testing.T) {
	var results []naabu.Result
	for i := 1; i <= 200; i++ {
		ip := "10.0." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250)
		results = append(results, n("", ip, 80), n("", ip, 6379))
		if i%2 == 0 {
			results = append(results, n("", ip, 8080))
		}
	}
	out := Reduce(results, nil, Defaults())
	res := schema.Result{Tool: "raijin-ports", Findings: out.Findings, Groups: out.Groups, Omitted: map[string]int{}, Budget: schema.Budget{MaxBytes: 2000}}
	Fit(&res, 2000)
	if size(res) > 2000 || !res.Budget.Truncated {
		t.Fatalf("size %d truncated %v", size(res), res.Budget.Truncated)
	}
	// the two groups (80, and 80 plus 8080) lose their 200 hosts, then the groups go, then the finding
	// keeps one location of 200
	if res.Omitted["locations"] != 200+199 || res.Omitted["groups"] != 2 || len(res.Findings) != 1 || res.Findings[0].Count != 200 {
		t.Errorf("omitted %v findings %+v", res.Omitted, res.Findings)
	}
	b, _ := schema.Marshal(res)
	if !strings.Contains(string(b), `"locations":["10.0.0.1:6379"],"count":200`) {
		t.Errorf("a cut finding keeps its count: %s", b)
	}
}

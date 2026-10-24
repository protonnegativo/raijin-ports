// Package reduce turns raw naabu and nmap results into a small, ranked Raijin result.
//
// It is lossless for what an agent acts on: every open port naabu found (host, IP, port, protocol) is
// kept, with the service, product, version and extra information nmap identified on it. Hosts with the
// same set of open ports collapse into one group that lists every host. Only exact duplicates are
// dropped. A byte budget can cut, but every cut is counted in omitted.
package reduce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/protonnegativo/raijin-ports/internal/naabu"
	"github.com/protonnegativo/raijin-ports/internal/nmap"
	"github.com/protonnegativo/raijin-ports/internal/schema"
)

// Options control what the reducer keeps.
type Options struct {
	MaxItems int // 0 keeps every finding
	MaxBytes int
	// OutlierMin is the number of hosts (distinct IPs) a run needs before a port open on one host only
	// is an outlier, and OutlierMaxPorts the number of open ports above which a host answers on too many
	// ports for one of them to stand out (a firewall or tarpit). See Reduce.
	OutlierMin      int
	OutlierMaxPorts int
	InScope         func(target string) bool
}

// Defaults keep every finding. 32,000 bytes holds about 400 hosts with a few ports each.
func Defaults() Options {
	return Options{MaxBytes: 32000, OutlierMin: 4, OutlierMaxPorts: 32}
}

// Severity of each rule. A finding has one category tag at most, so this is its severity.
//
//	datastore     a database, cache, search engine or queue (MySQL, PostgreSQL, Redis, MongoDB,
//	              Elasticsearch, Memcached...): high
//	admin-api     an API or console that controls infrastructure or runs code (Docker API, kubelet, etcd,
//	              Jenkins, Consul, JDWP...): high
//	remote-admin  RDP, VNC, Telnet, SMB, WinRM, X11, the r-services, SSH on a port other than 22: medium
//	file-share    FTP, TFTP, NFS, rpcbind, rsync, AFP: medium
//	outlier       a port that only one host has open, in a run with a common baseline: low, heuristic
var severities = map[string]string{
	"datastore":    "high",
	"admin-api":    "high",
	"remote-admin": "medium",
	"file-share":   "medium",
	"outlier":      "low",
}

// Output is what Reduce returns.
type Output struct {
	Findings []schema.Finding
	Groups   []schema.Group
	Omitted  map[string]int
	// AllLocations is every location per finding fingerprint, before any budget, for --state.
	AllLocations map[string][]string
	Hosts        int // distinct hosts with an open port
	Ports        int // distinct open ports (host, IP, port, protocol)
}

// entry is one open port on one host.
type entry struct {
	host     string // the scanned name, "" when the target was an IP
	ip       string
	port     int
	protocol string
	tls      bool
	services []schema.Service
}

type cluster struct {
	key   string
	svc   schema.Service
	tags  []string
	guess bool
	name  string
	locs  map[string]bool
}

// Reduce collapses the results into findings and groups. A port that matches a rule goes to a finding
// that lists every host:port with the same service; every other port goes to its host's group, and
// hosts with exactly the same other ports share one group.
//
// A port no rule matched is an outlier when the run has a baseline (at least OutlierMin hosts, and one
// port that at least half of them have open) and only one host has it open, unless nmap saw it closed
// or tcpwrapped, or that host has OutlierMaxPorts open ports or more. nmap ports with no naabu result (an nmap run
// of its own, read with --input) are results too, when nmap says they are open.
func Reduce(results []naabu.Result, ports []nmap.Port, opt Options) Output {
	out := Output{Omitted: map[string]int{}, AllLocations: map[string][]string{}}
	entries := map[string]*entry{}
	var order []string
	dropped := map[string]bool{}

	add := func(host, ip string, port int, protocol string) (*entry, bool) {
		host = normalizeHost(host)
		ip = strings.TrimSpace(ip)
		if host == ip || net.ParseIP(host) != nil && ip == "" {
			host, ip = "", firstNonEmpty(ip, host)
		}
		protocol = strings.ToLower(firstNonEmpty(protocol, "tcp"))
		key := fmt.Sprintf("%s\x00%s\x00%d/%s", host, ip, port, protocol)
		target := firstNonEmpty(host, ip)
		if opt.InScope != nil && !opt.InScope(target) {
			if !dropped[key] {
				dropped[key] = true
				out.Omitted["out_of_scope"]++
			}
			return nil, false
		}
		if e, ok := entries[key]; ok {
			return e, true
		}
		e := &entry{host: host, ip: ip, port: port, protocol: protocol}
		entries[key] = e
		order = append(order, key)
		return e, false
	}

	for _, r := range results {
		e, dup := add(r.Host, r.IP, r.Port, r.Protocol)
		if e == nil {
			continue
		}
		if dup {
			out.Omitted["duplicates"]++
		}
		e.tls = e.tls || r.TLS
	}

	// nmap answers are joined to naabu's ports by IP, port and protocol.
	byAddr := map[string][]*entry{}
	for _, k := range order {
		e := entries[k]
		a := addrKey(e.ip, e.port, e.protocol)
		byAddr[a] = append(byAddr[a], e)
	}
	for _, p := range ports {
		svc := service(p)
		targets := byAddr[addrKey(p.IP, p.Port, p.Protocol)]
		if len(targets) == 0 {
			if !strings.HasPrefix(p.State, "open") {
				continue // nmap's own closed and filtered ports are not results
			}
			e, _ := add(p.Host, p.IP, p.Port, p.Protocol)
			if e == nil {
				continue
			}
			targets = []*entry{e}
			byAddr[addrKey(p.IP, p.Port, p.Protocol)] = targets
		}
		for _, e := range targets {
			if !hasService(e.services, svc) {
				e.services = append(e.services, svc)
			}
		}
	}

	// A port open on one host only is an outlier when the run has a baseline: at least OutlierMin hosts,
	// and one port that at least half of them have open.
	ipsPerPort := map[string]map[string]bool{}
	allIPs := map[string]bool{}
	for _, k := range order {
		e := entries[k]
		pk := strconv.Itoa(e.port) + "/" + e.protocol
		if ipsPerPort[pk] == nil {
			ipsPerPort[pk] = map[string]bool{}
		}
		id := firstNonEmpty(e.ip, e.host)
		ipsPerPort[pk][id] = true
		allIPs[id] = true
	}
	baseline := 0
	for _, s := range ipsPerPort {
		baseline = max(baseline, len(s))
	}
	outliers := opt.OutlierMin > 0 && len(allIPs) >= opt.OutlierMin && baseline*2 >= len(allIPs)
	portsPerIP := map[string]int{}
	for _, k := range order {
		portsPerIP[firstNonEmpty(entries[k].ip, entries[k].host)]++
	}

	clusters := map[string]*cluster{}
	var keys []string
	hostPorts := map[string]map[string]bool{} // host location -> port strings that went to no finding
	var hostOrder []string
	for _, k := range order {
		e := entries[k]
		hl := HostLocation(e.host, e.ip)
		if _, ok := hostPorts[hl]; !ok {
			hostPorts[hl] = map[string]bool{}
			hostOrder = append(hostOrder, hl)
		}
		svcs := e.services
		if len(svcs) == 0 {
			svcs = []schema.Service{{Protocol: e.protocol}}
		}
		for _, svc := range svcs {
			svc = fill(svc, e)
			cat, guess, name := classify(svc, e.port)
			var tags []string
			if cat != "" {
				tags = []string{cat}
			} else if outliers && len(ipsPerPort[strconv.Itoa(e.port)+"/"+e.protocol]) == 1 && svc.State == "" &&
				strings.TrimPrefix(svc.Service, "ssl/") != "tcpwrapped" && portsPerIP[firstNonEmpty(e.ip, e.host)] < opt.OutlierMaxPorts {
				tags = []string{"outlier"}
				name = firstNonEmpty(svc.Product, strings.TrimSuffix(svc.Service, "?"), "port "+strconv.Itoa(e.port))
			}
			if len(tags) == 0 {
				hostPorts[hl][PortString(e.port, svc)] = true
				continue
			}
			ck := clusterKey(svc, tags)
			c, ok := clusters[ck]
			if !ok {
				c = &cluster{key: ck, svc: svc, tags: tags, guess: guess, name: name, locs: map[string]bool{}}
				clusters[ck] = c
				keys = append(keys, ck)
			}
			c.locs[Location(e.host, e.ip, e.port)] = true
		}
	}
	out.Hosts = len(hostOrder)
	out.Ports = len(order)

	findings := []schema.Finding{}
	for _, key := range keys {
		c := clusters[key]
		locs := sortedLocations(c.locs)
		id := c.tags[0] + "-" + fingerprint(key)[:8]
		f := schema.Finding{ID: id, Title: Title(c.tags[0], c.svc, c.name), Severity: severities[c.tags[0]], Tags: c.tags,
			Service: c.svc, Locations: locs, Count: len(locs), Fingerprint: fingerprint(id)}
		if c.guess || c.tags[0] == "outlier" {
			f.Confidence = "heuristic"
		}
		out.AllLocations[f.Fingerprint] = locs
		findings = append(findings, f)
	}

	groupsByKey := map[string]*schema.Group{}
	var groupKeys []string
	for _, hl := range hostOrder {
		set := hostPorts[hl]
		if len(set) == 0 {
			continue // every port of this host is in a finding
		}
		ps := Ranges(sortedPorts(set))
		key := strings.Join(ps, "\n")
		g, ok := groupsByKey[key]
		if !ok {
			g = &schema.Group{ID: groupPrefix(ps) + "-" + fingerprint(key)[:8], Ports: ps}
			groupsByKey[key] = g
			groupKeys = append(groupKeys, key)
		}
		g.Locations = append(g.Locations, hl)
	}
	groups := []schema.Group{}
	for _, k := range groupKeys {
		g := groupsByKey[k]
		g.Locations = sortedLocations(toSet(g.Locations))
		g.Count = len(g.Locations)
		groups = append(groups, *g)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if schema.ConfidenceRank[a.Confidence] != schema.ConfidenceRank[b.Confidence] {
			return schema.ConfidenceRank[a.Confidence] > schema.ConfidenceRank[b.Confidence]
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})

	if opt.MaxItems > 0 && len(findings) > opt.MaxItems {
		out.Omitted["findings"] += len(findings) - opt.MaxItems
		findings = findings[:opt.MaxItems]
	}
	out.Findings, out.Groups = findings, groups
	return out
}

// service is the schema view of an nmap port: "ssl/" is already part of the name, a service nmap named
// from its port table gets a "?", and the state is written only when it is not open.
func service(p nmap.Port) schema.Service {
	s := schema.Service{Protocol: strings.ToLower(p.Protocol), Service: p.Service, Product: p.Product, Version: p.Version, Info: p.Info}
	if p.Guess && identified(s.Service) {
		s.Service += "?"
	}
	if p.State != "open" {
		s.State = p.State
	}
	return s
}

// fill completes a service from naabu: with no name from nmap, the well-known service of the port is
// written as a guess ("ssl/" first when naabu saw TLS). TCP is the default protocol and is left out.
func fill(s schema.Service, e *entry) schema.Service {
	if s.Protocol == "" {
		s.Protocol = e.protocol
	}
	if s.Service == "" && s.State == "" {
		s.Service = Guess(e.port, s.Protocol)
		if e.tls && s.Service != "" && !strings.HasPrefix(s.Service, "ssl/") {
			s.Service = "ssl/" + s.Service
		}
	}
	if s.Protocol == "tcp" {
		s.Protocol = ""
	}
	return s
}

// classify returns the rule a service matches, whether that rests on a guess from the port number, and
// the name for the title. A service nmap identified is classified by its name and product; otherwise the
// well-known service of the port decides, and the finding is a guess.
func classify(s schema.Service, port int) (string, bool, string) {
	if identified(s.Service) {
		return Category(s.Service, s.Product, port), false, firstNonEmpty(s.Product, s.Service)
	}
	if c := Category(s.Service, s.Product, port); c != "" {
		return c, true, firstNonEmpty(s.Product, s.Service)
	}
	g := Guess(port, firstNonEmpty(s.Protocol, "tcp"))
	if g == "" {
		return "", false, ""
	}
	return Category(g, "", port), true, g
}

// Title is one line per finding.
func Title(tag string, s schema.Service, name string) string {
	switch tag {
	case "datastore":
		return "Exposed datastore: " + name
	case "admin-api":
		return "Exposed admin API: " + name
	case "remote-admin":
		if strings.TrimSuffix(strings.TrimPrefix(s.Service, "ssl/"), "?") == "ssh" {
			return "SSH on a non-standard port"
		}
		return "Remote admin: " + name
	case "file-share":
		return "File share: " + name
	}
	return "Port open on one host only: " + name
}

// PortString is one open port in a group: "443 ssl/http nginx 1.18.0 (Ubuntu)". It is the port ("/udp"
// for UDP), then the service, product, version and info as nmap's text output writes them, then the
// state nmap saw when it is not open: "8080 http-proxy? (nmap: closed)".
func PortString(port int, s schema.Service) string {
	p := strconv.Itoa(port)
	if s.Protocol == "udp" {
		p += "/udp"
	}
	if d := describe(s); d != "" {
		return p + " " + d
	}
	return p
}

func describe(s schema.Service) string {
	var parts []string
	for _, v := range []string{s.Service, s.Product, s.Version} {
		if v != "" {
			parts = append(parts, v)
		}
	}
	if s.Info != "" {
		parts = append(parts, "("+s.Info+")")
	}
	if s.State != "" {
		parts = append(parts, "(nmap: "+s.State+")")
	}
	return strings.Join(parts, " ")
}

// Ranges merges neighbouring ports with the same description into one string: "8000 tcpwrapped",
// "8001 tcpwrapped" and "8002 tcpwrapped" are "8000-8002 tcpwrapped". The input is sorted by port.
func Ranges(ports []string) []string {
	type run struct {
		first, last int
		suffix      string
	}
	var runs []run
	for _, s := range ports {
		head, desc, _ := strings.Cut(s, " ")
		num, proto, _ := strings.Cut(head, "/")
		n, err := strconv.Atoi(num)
		suffix := "/" + proto + " " + desc
		if err != nil {
			runs = append(runs, run{first: -1, suffix: s})
			continue
		}
		if l := len(runs); l > 0 && runs[l-1].first >= 0 && runs[l-1].last == n-1 && runs[l-1].suffix == suffix {
			runs[l-1].last = n
			continue
		}
		runs = append(runs, run{first: n, last: n, suffix: suffix})
	}
	out := make([]string, 0, len(runs))
	for _, r := range runs {
		if r.first < 0 {
			out = append(out, r.suffix)
			continue
		}
		p := strconv.Itoa(r.first)
		if r.last != r.first {
			p += "-" + strconv.Itoa(r.last)
		}
		proto, desc, _ := strings.Cut(r.suffix, " ")
		if proto != "/" {
			p += proto
		}
		out = append(out, strings.TrimSpace(p+" "+desc))
	}
	return out
}

// HostLocation is a host in a group: the IP, or "name [ip]" when the host is a name.
func HostLocation(host, ip string) string {
	switch {
	case host == "":
		return ip
	case ip == "":
		return host
	}
	return host + " [" + ip + "]"
}

// Location is a port in a finding: "ip:port", or "name:port [ip]" when the host is a name. IPv6
// addresses are in brackets: "[::1]:22".
func Location(host, ip string, port int) string {
	hp := net.JoinHostPort(firstNonEmpty(host, ip), strconv.Itoa(port))
	if host != "" && ip != "" {
		hp += " [" + ip + "]"
	}
	return hp
}

func clusterKey(s schema.Service, tags []string) string {
	b, _ := schema.Marshal([]any{tags, s.Protocol, s.Service, s.Product, s.Version, s.Info, s.State})
	return string(b)
}

func groupPrefix(ports []string) string {
	for _, p := range ports {
		if _, desc, _ := strings.Cut(p, " "); !strings.Contains(strings.SplitN(desc, " ", 2)[0], "http") {
			return "ports"
		}
	}
	return "web"
}

func hasService(list []schema.Service, s schema.Service) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func addrKey(ip string, port int, protocol string) string {
	return strings.TrimSpace(ip) + "|" + strconv.Itoa(port) + "|" + strings.ToLower(firstNonEmpty(protocol, "tcp"))
}

// normalizeHost lowercases a name and removes the trailing dot.
func normalizeHost(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// sortedPorts orders port strings by protocol (TCP first), then port number.
func sortedPorts(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	num := func(s string) (bool, int) {
		head, _, _ := strings.Cut(s, " ")
		n, _ := strconv.Atoi(strings.TrimSuffix(head, "/udp"))
		return strings.HasSuffix(head, "/udp"), n
	}
	sort.Slice(out, func(i, j int) bool {
		ui, ni := num(out[i])
		uj, nj := num(out[j])
		if ui != uj {
			return !ui
		}
		if ni != nj {
			return ni < nj
		}
		return out[i] < out[j]
	})
	return out
}

// sortedLocations orders hosts by IP (numerically) then name, so 10.0.0.9 comes before 10.0.0.10.
func sortedLocations(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := locKey(out[i]), locKey(out[j])
		if a != b {
			return a < b
		}
		return out[i] < out[j]
	})
	return out
}

// locKey sorts IPs before names, IPs numerically, ports numerically.
func locKey(loc string) string {
	head := strings.SplitN(loc, " ", 2)[0]
	host, port, err := net.SplitHostPort(head)
	if err != nil {
		host, port = head, ""
	}
	p, _ := strconv.Atoi(port)
	if ip := net.ParseIP(host); ip != nil {
		return fmt.Sprintf("0%x|%05d", []byte(ip.To16()), p)
	}
	return fmt.Sprintf("1%s|%05d", host, p)
}

func toSet(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, s := range list {
		m[s] = true
	}
	return m
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// group locations, then groups, then the locations of the lowest-ranked findings (each keeps one, and
// its count), then the lowest-ranked findings. Every cut is counted in Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res) // now includes the budget object
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		before := size(g)
		res.Omitted["locations"] += len(g.Locations)
		g.Locations = nil
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if len(f.Locations) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["locations"] += len(f.Locations) - 1
		f.Locations = f.Locations[:1]
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

func size(v any) int {
	b, _ := schema.Marshal(v)
	return len(b)
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

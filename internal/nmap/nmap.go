// Package nmap runs nmap service detection (-sV) on the ports naabu found open and parses its XML output.
package nmap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// ErrNotFound is returned when the nmap binary is not on PATH.
var ErrNotFound = errors.New("nmap binary not found")

// Port is one port of one host in nmap's output, with the service nmap identified on it.
type Port struct {
	IP       string
	Host     string // the name nmap was given, when it was given one
	Port     int
	Protocol string
	State    string // open, closed, filtered, open|filtered...
	// Service is nmap's service name, "ssl/" first when nmap found TLS in front of it.
	Service string
	Product string
	Version string
	Info    string
	// Guess is true when nmap named the service from its port table, not from a probe that matched.
	Guess bool
}

// Target is a port to identify: naabu found it open on IP.
type Target struct {
	IP       string
	Port     int
	Protocol string
}

// Options are the nmap settings Raijin passes through.
type Options struct {
	Binary string
	Extra  []string
	// Raw, if set, receives nmap's XML output unchanged.
	Raw io.Writer
	// Stats, if set, receives the count of ports in nmap's output and of ports without the fields Raijin
	// needs, summed over every run.
	Stats *Stats
}

// Stats counts the <port> elements nmap wrote (Ports) and those without a portid or a state, or on a host
// with no IP address (Bad). Bad ports are left out of the result: nmap's XML format may have changed.
type Stats struct {
	Ports, Bad int
}

// Run identifies the services on the targets. IPs with the same set of ports share one nmap run, so 40
// web servers with the same two ports cost one run. It returns every port nmap reported, plus the last
// stderr lines if a run failed.
func Run(ctx context.Context, targets []Target, opt Options) ([]Port, string, error) {
	bin := opt.Binary
	if bin == "" {
		bin = "nmap"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, "", ErrNotFound
	}
	var all []Port
	for _, b := range Batches(targets) {
		cmd := exec.CommandContext(ctx, path, Args(b, opt)...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		runErr := cmd.Run()
		if opt.Raw != nil {
			if _, err := opt.Raw.Write(stdout.Bytes()); err != nil {
				return all, "", err
			}
		}
		ports, st, parseErr := ParseStats(&stdout)
		if opt.Stats != nil {
			opt.Stats.Ports += st.Ports
			opt.Stats.Bad += st.Bad
		}
		all = append(all, ports...)
		if runErr != nil {
			return all, tail(stderr.String(), 3), fmt.Errorf("nmap exited: %w", runErr)
		}
		if parseErr != nil {
			return all, tail(stderr.String(), 3), parseErr
		}
	}
	return all, "", nil
}

// Batch is one nmap run: the IPs that share a port list, all IPv4 or all IPv6.
type Batch struct {
	IPs   []string
	TCP   []int
	UDP   []int
	IPv6  bool
	ports string
}

// Batches groups the targets by IP family and port list, in a stable order.
func Batches(targets []Target) []Batch {
	type set struct {
		tcp, udp map[int]bool
	}
	byIP := map[string]*set{}
	for _, t := range targets {
		s := byIP[t.IP]
		if s == nil {
			s = &set{tcp: map[int]bool{}, udp: map[int]bool{}}
			byIP[t.IP] = s
		}
		if strings.EqualFold(t.Protocol, "udp") {
			s.udp[t.Port] = true
		} else {
			s.tcp[t.Port] = true
		}
	}
	batches := map[string]*Batch{}
	var keys []string
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		s := byIP[ip]
		b := Batch{TCP: sortedInts(s.tcp), UDP: sortedInts(s.udp), IPv6: strings.Contains(ip, ":")}
		b.ports = PortSpec(b.TCP, b.UDP)
		key := fmt.Sprint(b.IPv6) + " " + b.ports
		if batches[key] == nil {
			batches[key] = &b
			keys = append(keys, key)
		}
		batches[key].IPs = append(batches[key].IPs, ip)
	}
	out := make([]Batch, 0, len(keys))
	for _, k := range keys {
		out = append(out, *batches[k])
	}
	return out
}

// Args builds the nmap command line: a TCP connect scan (-sT, plus -sU for UDP ports) of only the given
// ports, service detection (-sV), no host discovery (-Pn, naabu already found the ports open), no
// reverse DNS (-n) and XML on stdout. --nmap-args comes before the targets.
func Args(b Batch, opt Options) []string {
	args := []string{"-sT", "-sV", "-Pn", "-n", "-oX", "-"}
	if len(b.UDP) > 0 {
		args = append(args, "-sU")
	}
	if b.IPv6 {
		args = append(args, "-6")
	}
	ports := b.ports
	if ports == "" {
		ports = PortSpec(b.TCP, b.UDP)
	}
	args = append(args, "-p", ports)
	args = append(args, opt.Extra...)
	return append(args, b.IPs...)
}

// PortSpec is nmap's -p value: "22,80" for TCP only, "T:22,80,U:53" when there are UDP ports.
func PortSpec(tcp, udp []int) string {
	join := func(ports []int) string {
		s := make([]string, len(ports))
		for i, p := range ports {
			s[i] = strconv.Itoa(p)
		}
		return strings.Join(s, ",")
	}
	if len(udp) == 0 {
		return join(tcp)
	}
	var parts []string
	if len(tcp) > 0 {
		parts = append(parts, "T:"+join(tcp))
	}
	return strings.Join(append(parts, "U:"+join(udp)), ",")
}

type xmlRun struct {
	Hosts []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Hostnames []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostnames>hostname"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name      string `xml:"name,attr"`
				Product   string `xml:"product,attr"`
				Version   string `xml:"version,attr"`
				ExtraInfo string `xml:"extrainfo,attr"`
				Tunnel    string `xml:"tunnel,attr"`
				Method    string `xml:"method,attr"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

// Parse reads every nmap XML document (-oX) in r. Lines outside a document are skipped, so a file with
// naabu and nmap output, like the raw file, can be read by both parsers.
func Parse(r io.Reader) ([]Port, error) {
	ports, _, err := ParseStats(r)
	return ports, err
}

// ParseStats is Parse that also counts the ports, and the ports it left out.
func ParseStats(r io.Reader) ([]Port, Stats, error) {
	var ports []Port
	var st Stats
	var doc bytes.Buffer
	in := false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		t := bytes.TrimSpace(line)
		if !in && (bytes.HasPrefix(t, []byte("<?xml")) || bytes.HasPrefix(t, []byte("<nmaprun"))) {
			in = true
			doc.Reset()
		}
		if !in {
			continue
		}
		doc.Write(line)
		doc.WriteByte('\n')
		if bytes.Contains(t, []byte("</nmaprun>")) {
			in = false
			p, err := parseDoc(doc.Bytes(), &st)
			if err != nil {
				return ports, st, err
			}
			ports = append(ports, p...)
		}
	}
	if in {
		// nmap was stopped before it closed the document: keep the hosts it finished.
		p, _ := parseDoc(append(doc.Bytes(), "</nmaprun>\n"...), &st)
		ports = append(ports, p...)
	}
	return ports, st, sc.Err()
}

func parseDoc(b []byte, st *Stats) ([]Port, error) {
	var run xmlRun
	if err := xml.Unmarshal(b, &run); err != nil {
		return nil, fmt.Errorf("nmap XML: %w", err)
	}
	var out []Port
	for _, h := range run.Hosts {
		ip := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				ip = a.Addr
				break
			}
		}
		st.Ports += len(h.Ports)
		if net.ParseIP(ip) == nil {
			st.Bad += len(h.Ports)
			continue
		}
		host := ""
		for _, n := range h.Hostnames {
			if n.Type == "user" {
				host = n.Name
			}
		}
		for _, p := range h.Ports {
			if p.PortID <= 0 || p.State.State == "" {
				st.Bad++
				continue
			}
			s := p.Service
			name := s.Name
			if name != "" && s.Tunnel == "ssl" {
				name = "ssl/" + name
			}
			out = append(out, Port{
				IP: ip, Host: host, Port: p.PortID, Protocol: strings.ToLower(p.Protocol), State: p.State.State,
				Service: name, Product: s.Product, Version: s.Version, Info: s.ExtraInfo,
				Guess: s.Method == "table",
			})
		}
	}
	return out, nil
}

func sortedInts(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

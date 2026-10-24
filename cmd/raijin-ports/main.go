// Command raijin-ports runs naabu and nmap and returns a small, grouped, ranked result for AI agents.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"

	"github.com/protonnegativo/raijin-ports/internal/banner"
	"github.com/protonnegativo/raijin-ports/internal/naabu"
	"github.com/protonnegativo/raijin-ports/internal/nmap"
	"github.com/protonnegativo/raijin-ports/internal/reduce"
	"github.com/protonnegativo/raijin-ports/internal/schema"
	"github.com/protonnegativo/raijin-ports/internal/scope"
	"github.com/protonnegativo/raijin-ports/internal/state"
)

const version = "0.1.0"

// maxCIDR is the largest range a target can expand to (a /16). Each address is checked against the
// scope before naabu runs, so exclusions inside a range are never scanned.
const maxCIDR = 1 << 16

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-ports", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var hosts, inputs multi
	fs.Var(&hosts, "host", "host, IP or CIDR to scan, comma-separated (repeatable)")
	list := fs.String("l", "", "file with one host, IP or CIDR per line")
	scopeFile := fs.String("scope", "", "scope file (required): domains, *.wildcards, IPs, CIDRs, !exclusions")
	ports := fs.String("p", "", "ports to scan (naabu -p): 22,80,443 or 1-65535 (default: naabu's top 100)")
	topPorts := fs.String("top-ports", "", "top ports to scan (naabu -tp): 100, 1000 or full")
	noServices := fs.Bool("no-services", false, "only find open ports; do not run nmap service detection")
	nmapArgs := fs.String("nmap-args", "", "extra nmap arguments, space-separated (e.g. \"--version-intensity 9\")")
	rate := fs.Int("rate", 0, "packets per second (naabu -rate)")
	threads := fs.Int("threads", 0, "worker threads (naabu -c)")
	timeout := fs.Int("timeout", 0, "milliseconds to wait for each port (naabu -timeout)")
	maxItems := fs.Int("max-items", 0, "maximum findings in the output (0 keeps all)")
	maxBytes := fs.Int("max-bytes", reduce.Defaults().MaxBytes, "maximum size of the JSON output; cuts are counted in omitted")
	rawPath := fs.String("raw", "", "file for naabu's JSONL and nmap's XML output (default: a new file in the temp dir)")
	statePath := fs.String("state", "", "state file; marks findings that are new since the last run")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	fs.Var(&inputs, "input", "read existing naabu JSONL or text and/or nmap XML instead of running them (repeatable)")
	naabuBin := fs.String("naabu", "naabu", "path to the naabu binary")
	nmapBin := fs.String("nmap", "nmap", "path to the nmap binary")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-ports --scope scope.txt (-host target | -l targets.txt | --input results) [flags] [-- extra naabu args]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-ports", version, useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, "raijin-ports", version)
		return 0
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-ports: --scope is required")
		return 1
	}
	sc, err := scope.Load(*scopeFile)
	if err != nil {
		fmt.Fprintln(stderr, "raijin-ports: scope:", err)
		return 1
	}

	res := schema.Result{
		Tool:     "raijin-ports",
		Version:  version,
		Findings: []schema.Finding{},
		Groups:   []schema.Group{},
		Omitted:  map[string]int{},
		Errors:   []schema.Error{},
		Next:     []string{},
		Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}
	opt := reduce.Defaults()
	opt.MaxItems = *maxItems
	opt.MaxBytes = *maxBytes
	opt.InScope = sc.Allowed

	var results []naabu.Result
	var services []nmap.Port
	checked := false
	code := 0
	if len(inputs) > 0 {
		for _, in := range inputs {
			b, err := os.ReadFile(in)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-ports:", err)
				return 1
			}
			r, err1 := naabu.Parse(bytes.NewReader(b))
			p, err2 := nmap.Parse(bytes.NewReader(b))
			if err := errors.Join(err1, err2); err != nil {
				fmt.Fprintln(stderr, "raijin-ports:", err)
				return 1
			}
			results = append(results, r...)
			services = append(services, p...)
		}
		// A replay never runs an engine: services are checked when the input has nmap output.
		checked = len(services) > 0
		res.Target = strings.Join(inputs, ", ")
	} else {
		if *list != "" {
			lines, err := readLines(*list)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-ports:", err)
				return 1
			}
			hosts = append(hosts, lines...)
		}
		targets, err := filter(hosts, sc, res.Omitted)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-ports:", err)
			return 1
		}
		if len(targets) == 0 {
			fmt.Fprintln(stderr, "raijin-ports: no targets in scope")
			return 1
		}
		res.Target = targetSummary(targets, res.Omitted["out_of_scope"])

		if *rawPath == "" {
			f, err := os.CreateTemp("", "raijin-ports-*.raw")
			if err != nil {
				fmt.Fprintln(stderr, "raijin-ports:", err)
				return 1
			}
			f.Close()
			*rawPath = f.Name()
		}
		raw, err := os.Create(*rawPath)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-ports:", err)
			return 1
		}
		defer raw.Close()
		res.Raw = *rawPath

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		var stderrTail string
		results, stderrTail, err = naabu.Run(ctx, targets, naabu.Options{
			Binary: *naabuBin, Ports: *ports, TopPorts: *topPorts, Rate: *rate, Threads: *threads, Timeout: *timeout,
			Extra: fs.Args(), Raw: raw,
		})
		switch {
		case errors.Is(err, naabu.ErrNotFound):
			res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install naabu (go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest) or pass --naabu <path>"})
			res.Summary = "naabu not found, nothing scanned"
			res.Raw = ""
			raw.Close()
			os.Remove(*rawPath)
			write(stdout, &res, *format, *pretty)
			return 2
		case err != nil:
			res.Errors = append(res.Errors, engineError(err, stderrTail))
		}

		if t := nmapTargets(results, sc); !*noServices && len(t) > 0 {
			services, stderrTail, err = nmap.Run(ctx, t, nmap.Options{Binary: *nmapBin, Extra: strings.Fields(*nmapArgs), Raw: raw})
			switch {
			case errors.Is(err, nmap.ErrNotFound):
				res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install nmap (apt install nmap, brew install nmap) or pass --nmap <path>, or --no-services; the ports below have no service detection"})
				code = 2
			case err != nil:
				res.Errors = append(res.Errors, engineError(err, stderrTail))
				checked = true
			default:
				checked = true
			}
		}
	}

	out := reduce.Reduce(results, services, opt)
	res.Findings, res.Groups = out.Findings, out.Groups
	for k, v := range out.Omitted {
		res.Omitted[k] += v
	}

	newCount := -1
	if *statePath != "" {
		st, err := state.Load(*statePath)
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
		} else {
			newCount = st.Mark(res.Findings, out.AllLocations)
			if err := st.Save(*statePath); err != nil {
				res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
			}
		}
	}

	res.Summary = summary(res, out, checked, newCount)
	if res.Omitted["findings"] > 0 {
		res.Budget.Truncated = true
	}
	reduce.Fit(&res, *maxBytes)
	if res.Budget.Truncated {
		hint := "raise --max-bytes"
		if src := res.Raw + strings.Join(inputs, ", "); src != "" {
			hint += " or read " + src + " for what was cut"
		}
		res.Next = append(res.Next, hint)
	}
	write(stdout, &res, *format, *pretty)
	return code
}

func engineError(err error, stderrTail string) schema.Error {
	hint := err.Error()
	if stderrTail != "" {
		hint += ": " + stderrTail
	}
	return schema.Error{Kind: "engine_error", Hint: hint}
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// filter keeps the targets the scope allows. A CIDR is expanded and each address is checked on its own,
// so an exclusion inside a range is never scanned; out-of-scope targets are counted per address.
func filter(raw []string, sc *scope.Scope, omitted map[string]int) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	keep := func(t string) {
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		if !sc.Allowed(t) {
			omitted["out_of_scope"]++
			return
		}
		out = append(out, t)
	}
	for _, line := range raw {
		for _, t := range strings.Split(line, ",") {
			t = strings.ToLower(strings.TrimSpace(t))
			if !strings.Contains(t, "/") {
				keep(strings.TrimSuffix(t, "."))
				continue
			}
			ips, err := expand(t)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				keep(ip)
			}
		}
	}
	return out, nil
}

// expand lists every address in a CIDR, up to maxCIDR.
func expand(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %v", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 16 {
		return nil, fmt.Errorf("target %q has more than %d addresses; split it", cidr, maxCIDR)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	ip = ip.Mask(ipnet.Mask)
	var out []string
	for cur := append(net.IP(nil), ip...); ipnet.Contains(cur); cur = next(cur) {
		out = append(out, cur.String())
		if len(out) >= maxCIDR {
			break
		}
	}
	return out, nil
}

func next(ip net.IP) net.IP {
	n := append(net.IP(nil), ip...)
	for i := len(n) - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
	return n
}

// nmapTargets is what nmap identifies: every open port naabu found whose host is in scope, once per IP.
func nmapTargets(results []naabu.Result, sc *scope.Scope) []nmap.Target {
	seen := map[string]bool{}
	var out []nmap.Target
	for _, r := range results {
		target := r.Host
		if target == "" {
			target = r.IP
		}
		if net.ParseIP(r.IP) == nil || !sc.Allowed(target) {
			continue
		}
		k := fmt.Sprintf("%s|%d|%s", r.IP, r.Port, r.Protocol)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, nmap.Target{IP: r.IP, Port: r.Port, Protocol: r.Protocol})
	}
	return out
}

func targetSummary(targets []string, skipped int) string {
	s := fmt.Sprintf("%d target(s)", len(targets))
	if len(targets) == 1 {
		s = targets[0]
	}
	if skipped > 0 {
		s += fmt.Sprintf(" (%d out of scope skipped)", skipped)
	}
	return s
}

// summary is written before the budget, so it stays true when Fit cuts.
func summary(res schema.Result, out reduce.Output, checked bool, newCount int) string {
	bySev := map[string]int{}
	for _, f := range res.Findings {
		bySev[f.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	s := fmt.Sprintf("%d hosts, %d open ports", out.Hosts, out.Ports)
	if !checked {
		s += " (services not checked)"
	}
	s += fmt.Sprintf(", %d findings", len(res.Findings))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	s += fmt.Sprintf(", %d groups", len(res.Groups))
	if newCount >= 0 {
		s += fmt.Sprintf(", %d new", newCount)
	}
	return s
}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		for _, f := range res.Findings {
			mark := ""
			if f.New {
				mark = " [new]"
			}
			fmt.Fprintf(w, "%-8s %s %s (%d)%s\n", strings.ToUpper(f.Severity), strings.Join(f.Tags, ","), f.Title, max(f.Count, len(f.Locations)), mark)
			for _, l := range f.Locations {
				fmt.Fprintf(w, "         %s\n", l)
			}
		}
		for _, g := range res.Groups {
			n, unit := max(g.Count, len(g.Locations)), "hosts"
			if n == 1 {
				unit = "host"
			}
			fmt.Fprintf(w, "group    %s (%d %s)\n", strings.Join(g.Ports, ", "), n, unit)
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(res)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

// Package naabu runs the ProjectDiscovery naabu binary and parses its JSONL output.
package naabu

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ErrNotFound is returned when the naabu binary is not on PATH.
var ErrNotFound = errors.New("naabu binary not found")

// Result is the subset of a naabu JSONL result that Raijin uses: the open port and where it is. Host is
// the name that was scanned, empty when the target was an IP.
type Result struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	TLS      bool   `json:"tls"`
}

// Options are the naabu settings Raijin passes through.
type Options struct {
	Binary   string
	Ports    string // -p
	TopPorts string // -tp
	Rate     int    // -rate
	Threads  int    // -c
	Timeout  int    // -timeout, milliseconds
	Extra    []string
	// Raw, if set, receives naabu's JSONL output unchanged.
	Raw io.Writer
	// Stats, if set, receives the count of output lines and of lines that were not a result.
	Stats *Stats
}

// Stats counts naabu's output lines (Lines) and those that had no ip or host, and port (Bad): with -json
// every line should be a result, so a bad line means naabu's output format may have changed.
type Stats struct {
	Lines, Bad int
}

// Run scans the targets and returns every open port, plus the last stderr lines if naabu failed.
func Run(ctx context.Context, targets []string, opt Options) ([]Result, string, error) {
	bin := opt.Binary
	if bin == "" {
		bin = "naabu"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, "", ErrNotFound
	}

	list, err := os.CreateTemp("", "raijin-ports-targets-*.txt")
	if err != nil {
		return nil, "", err
	}
	defer os.Remove(list.Name())
	if _, err := io.WriteString(list, strings.Join(targets, "\n")+"\n"); err != nil {
		list.Close()
		return nil, "", err
	}
	list.Close()

	cmd := exec.CommandContext(ctx, path, Args(list.Name(), opt)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", err
	}
	var r io.Reader = stdout
	if opt.Raw != nil {
		r = io.TeeReader(stdout, opt.Raw)
	}
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}
	results, st, parseErr := ParseStats(r, true)
	if opt.Stats != nil {
		*opt.Stats = st
	}
	waitErr := cmd.Wait()
	if parseErr != nil {
		return results, tail(stderr.String(), 3), parseErr
	}
	if waitErr != nil {
		return results, tail(stderr.String(), 3), fmt.Errorf("naabu exited: %w", waitErr)
	}
	return results, "", nil
}

// Args builds the naabu command line. -s c is a TCP connect scan, which needs no raw sockets; anything
// after -- on the raijin-ports command line comes last, so it can override it.
func Args(listFile string, opt Options) []string {
	args := []string{"-l", listFile, "-s", "c", "-json", "-silent", "-nc", "-duc", "-no-stdin"}
	if opt.Ports != "" {
		args = append(args, "-p", opt.Ports)
	}
	if opt.TopPorts != "" {
		args = append(args, "-tp", opt.TopPorts)
	}
	if opt.Rate > 0 {
		args = append(args, "-rate", fmt.Sprint(opt.Rate))
	}
	if opt.Threads > 0 {
		args = append(args, "-c", fmt.Sprint(opt.Threads))
	}
	if opt.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprint(opt.Timeout))
	}
	return append(args, opt.Extra...)
}

// Parse reads naabu JSONL, and naabu's text output (one host:port per line). Other lines are skipped,
// so a file with naabu and nmap output can be read by both parsers.
func Parse(r io.Reader) ([]Result, error) {
	results, _, err := ParseStats(r, false)
	return results, err
}

// ParseStats is Parse that also counts the lines. JSON lines without the fields Raijin needs are bad; with
// strict (naabu's own -json stdout), so is every line that is not JSON.
func ParseStats(r io.Reader, strict bool) ([]Result, Stats, error) {
	var results []Result
	var st Stats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if line[0] != '{' {
			if strict {
				st.Lines++
				st.Bad++
				continue
			}
			if res, ok := parseText(string(line)); ok {
				results = append(results, res)
			}
			continue
		}
		st.Lines++
		var res Result
		if err := json.Unmarshal(line, &res); err != nil || res.IP == "" && res.Host == "" || res.Port <= 0 {
			st.Bad++
			continue
		}
		if res.Protocol == "" {
			res.Protocol = "tcp"
		}
		results = append(results, res)
	}
	return results, st, sc.Err()
}

// parseText reads "host:port" or "[v6]:port". A host that is an IP is the IP, otherwise it is a name
// whose IP the text output does not say.
func parseText(line string) (Result, bool) {
	if strings.ContainsAny(line, " \t<>\"{}") {
		return Result{}, false
	}
	host, port, err := net.SplitHostPort(line)
	if err != nil || host == "" {
		return Result{}, false
	}
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return Result{}, false
	}
	res := Result{Port: p, Protocol: "tcp"}
	if net.ParseIP(host) != nil {
		res.IP = host
	} else {
		res.Host = host
	}
	return res, true
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

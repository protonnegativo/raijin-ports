// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Nothing the engines found is dropped silently: every open port is listed, in a finding or in a group,
// and anything a budget cuts is counted in Omitted. What an agent can rebuild is left out of the JSON to
// save tokens: empty lists, the budget when nothing was cut, a count equal to the locations listed, and
// fields at their documented default.
//
// raijin-ports adds the service nmap identified (service, product, version, info) to findings, and the
// list of open ports to groups: it is what an agent reads to pick its next targets.
package schema

import (
	"bytes"
	"encoding/json"
)

// Marshal is json.Marshal without HTML escaping: "->" stays "->" instead of "->", which costs
// tokens and nothing else.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Result is the top-level object a Raijin tool writes to stdout.
type Result struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Target   string         `json:"target"`
	Summary  string         `json:"summary"`
	Findings []Finding      `json:"findings"`
	Groups   []Group        `json:"groups"`
	Omitted  map[string]int `json:"omitted,omitempty"`
	Errors   []Error        `json:"errors,omitempty"`
	Next     []string       `json:"next,omitempty"`
	// Raw is the file with the engine's full output, for details the result leaves out.
	Raw    string `json:"raw,omitempty"`
	Budget Budget `json:"budget"`
}

// MarshalJSON writes the budget only when something was cut.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	out := struct {
		plain
		Budget *Budget `json:"budget,omitempty"`
	}{plain: plain(r)}
	if r.Budget.Truncated {
		out.Budget = &r.Budget
	}
	return Marshal(out)
}

// Service is what runs on every port of a finding. Zero values are left out: no protocol means tcp, no
// state means open, no product, version or info means nmap had none.
type Service struct {
	// Protocol is "udp" for UDP ports; TCP is the default and is left out.
	Protocol string `json:"protocol,omitempty"`
	// Service is nmap's service name ("ssh", "http", "ssl/http"). A trailing "?" marks a guess from the
	// port number, made when nmap did not run or could not identify the service.
	Service string `json:"service,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	// Info is nmap's extra information ("Ubuntu Linux; protocol 2.0").
	Info string `json:"info,omitempty"`
	// State is nmap's port state when it is not open (naabu found it open, nmap did not): closed, filtered.
	State string `json:"state,omitempty"`
}

// Finding is one service worth acting on (an exposed database, remote admin, a Docker API, a port only
// one host has open) with every host:port that runs it.
// The same tool and ID in two runs is the same finding.
type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Confidence is "verified" or "heuristic"; empty means "matched".
	Confidence string `json:"confidence,omitempty"`
	// Tags are the rules that made it a finding: datastore, admin-api, remote-admin, file-share, outlier.
	Tags []string `json:"tags"`
	Service
	// Locations are every host:port with this service: "10.0.0.5:6379", or "db.example.com:6379 [10.0.0.5]"
	// when the host is a name.
	Locations []string `json:"locations"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	// Fingerprint is the internal key for --state; it is derived from the ID and not written.
	Fingerprint string `json:"-"`
	New         bool   `json:"new,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (f Finding) MarshalJSON() ([]byte, error) {
	type plain Finding
	p := plain(f)
	if p.Count <= len(p.Locations) {
		p.Count = 0
	}
	return Marshal(p)
}

// Group is a set of open ports that no rule flagged, with every host that has exactly that set open. 40
// web servers with the same two ports and the same server are one group.
type Group struct {
	ID string `json:"id"`
	// Ports are the open ports, one string each: "443 ssl/http nginx 1.18.0 (Ubuntu)", that is the port
	// ("/udp" for UDP), the service, the product, the version and the info in parentheses. Neighbouring
	// ports with the same service are one range: "8000-8099 tcpwrapped".
	Ports []string `json:"ports"`
	// Locations are the hosts: "10.0.0.5", or "web.example.com [10.0.0.5]" when the host is a name.
	Locations []string `json:"locations,omitempty"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (g Group) MarshalJSON() ([]byte, error) {
	type plain Group
	p := plain(g)
	if p.Count <= len(p.Locations) {
		p.Count = 0
	}
	return Marshal(p)
}

// Error is a problem during the run, with a hint about what to try next.
type Error struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
}

// Budget reports the output limits that were applied.
type Budget struct {
	MaxItems  int  `json:"max_items"`
	MaxBytes  int  `json:"max_bytes"`
	Truncated bool `json:"truncated"`
}

// SeverityRank orders severities from most to least important.
var SeverityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
	"unknown":  0,
}

// ConfidenceRank orders confidence values: a verified finding before a matched one before a heuristic one.
var ConfidenceRank = map[string]int{
	"verified":  2,
	"":          1,
	"heuristic": 0,
}

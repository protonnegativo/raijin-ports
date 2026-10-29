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

import core "github.com/protonnegativo/raijin-core/schema"

// The envelope (Result, Error, Budget, Marshal and the rank tables) lives in raijin-core; Finding and Group
// stay here because their fields are this tool's contract with raijin-diff and raijin-mcp.
type (
	Result = core.Result[Finding, Group]
	Error  = core.Error
	Budget = core.Budget
)

var (
	Marshal        = core.Marshal
	SeverityRank   = core.SeverityRank
	ConfidenceRank = core.ConfidenceRank
)

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
	p.Count = core.OmitCount(p.Count, len(p.Locations))
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
	p.Count = core.OmitCount(p.Count, len(p.Locations))
	return Marshal(p)
}

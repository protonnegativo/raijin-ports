package engine

import (
	"strings"
	"testing"
)

func TestTestedHasEveryEngine(t *testing.T) {
	m, err := Tested()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"naabu", "nmap"} {
		e, ok := m[name]
		if !ok {
			t.Fatalf("engines.json has no %s", name)
		}
		if _, _, ok := ParseVersion(e.Version); !ok || e.Go == "" && e.Pip == "" && e.System == "" {
			t.Errorf("%s: bad entry %+v", name, e)
		}
	}
}

func TestParseVersionOnRealOutput(t *testing.T) {
	for in, want := range map[string]string{
		// naabu -version -duc (stderr, after the banner)
		"\n                  __\n  ___  ___  ___ _/ /  __ __\n\t\tprojectdiscovery.io\n\n[INF] Current Version: 2.6.1\n": "2.6.1",
		"[\x1b[34mINF\x1b[0m] Current Version: v2.3.0\n":                                                                 "2.3.0",
		// nmap --version
		"Nmap version 7.94SVN ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu\nCompiled with: liblua-5.4.6 openssl-3.0.13\n": "7.94",
		"Nmap version 7.95 ( https://nmap.org )\n": "7.95",
	} {
		if _, got, ok := ParseVersion(in); !ok || got != want {
			t.Errorf("%q: got %q %v, want %q", in, got, ok, want)
		}
	}
	if _, _, ok := ParseVersion("command not found"); ok {
		t.Error("parsed a version from no version")
	}
}

func TestUntested(t *testing.T) {
	e := Engine{Version: "2.6.1", Go: "github.com/projectdiscovery/naabu/v2/cmd/naabu"}
	for out, warn := range map[string]bool{
		"Current Version: 2.6.1": false,
		"Current Version: 2.6.2": false, // newer patch: the drift job covers it
		"Current Version: 2.7.0": false,
		"Current Version: 2.6.0": true, // older
		"Current Version: 2.5.9": true,
		"Current Version: 3.0.0": true, // other major
		"Current Version: 1.9.9": true,
		"garbage":                false, // unparseable is silent
	} {
		h := hint("naabu", out, e)
		if (h != "") != warn {
			t.Errorf("%q: hint %q", out, h)
		}
		if warn && !strings.Contains(h, "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1") {
			t.Errorf("%q: hint %q has no install command", out, h)
		}
	}
	if h := hint("nmap", "Nmap version 7.93 ( https://nmap.org )", Engine{Version: "7.94", System: "nmap"}); !strings.Contains(h, "nmap 7.93 is not the tested 7.94") || !strings.Contains(h, "apt install nmap") {
		t.Errorf("nmap hint %q", h)
	}
}

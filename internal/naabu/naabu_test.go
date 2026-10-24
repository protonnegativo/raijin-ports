package naabu

import (
	"strings"
	"testing"
)

func TestParseJSONAndText(t *testing.T) {
	in := `{"ip":"127.0.0.1","timestamp":"2026-10-24T21:36:56Z","port":19080,"protocol":"tcp","tls":false}
{"host":"localhost","ip":"127.0.0.1","port":19080,"protocol":"tcp","tls":true}
not a result
<nmaprun scanner="nmap">
10.0.0.5:22
db.example.com:5432
[2001:db8::1]:443
{"ip":"10.0.0.1"}
`
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Result{
		{IP: "127.0.0.1", Port: 19080, Protocol: "tcp"},
		{Host: "localhost", IP: "127.0.0.1", Port: 19080, Protocol: "tcp", TLS: true},
		{IP: "10.0.0.5", Port: 22, Protocol: "tcp"},
		{Host: "db.example.com", Port: 5432, Protocol: "tcp"},
		{IP: "2001:db8::1", Port: 443, Protocol: "tcp"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestArgsUseConnectScanAndLetExtraArgsOverride(t *testing.T) {
	got := strings.Join(Args("list.txt", Options{Ports: "19000-19999", Rate: 500, Extra: []string{"-s", "s"}}), " ")
	want := "-l list.txt -s c -json -silent -nc -duc -no-stdin -p 19000-19999 -rate 500 -s s"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

package nmap

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestParseMixedFile(t *testing.T) {
	b, err := os.ReadFile("../../testdata/sample.raw")
	if err != nil {
		t.Fatal(err)
	}
	ports, err := Parse(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 27 {
		t.Errorf("got %d ports", len(ports))
	}
	byKey := map[string]Port{}
	for _, p := range ports {
		byKey[p.IP+" "+p.Protocol+" "+strconv.Itoa(p.Port)] = p
	}
	if p := byKey["10.0.0.1 tcp 443"]; p.Service != "ssl/http" || p.Product != "nginx" || p.Version != "1.18.0" || p.Info != "Ubuntu" {
		t.Errorf("ssl tunnel: %+v", p)
	}
	if p := byKey["2001:db8::5 tcp 2375"]; p.Service != "docker" {
		t.Errorf("ipv6: %+v", p)
	}
	if p := byKey["10.0.0.6 udp 53"]; p.Product != "dnsmasq" {
		t.Errorf("udp: %+v", p)
	}
	if p := byKey["10.0.0.7 tcp 8080"]; p.State != "closed" || !p.Guess {
		t.Errorf("closed, guessed from the port table: %+v", p)
	}
}

func TestParseKeepsAnUnfinishedDocument(t *testing.T) {
	in := `<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host>
`
	ports, err := Parse(strings.NewReader(in))
	if err != nil || len(ports) != 1 || ports[0].Service != "ssh" {
		t.Errorf("ports %+v err %v", ports, err)
	}
}

func TestBatchesShareARunPerPortList(t *testing.T) {
	targets := []Target{
		{IP: "10.0.0.2", Port: 80, Protocol: "tcp"}, {IP: "10.0.0.2", Port: 443, Protocol: "tcp"},
		{IP: "10.0.0.1", Port: 443, Protocol: "tcp"}, {IP: "10.0.0.1", Port: 80, Protocol: "tcp"},
		{IP: "10.0.0.3", Port: 22, Protocol: "tcp"}, {IP: "10.0.0.3", Port: 53, Protocol: "udp"},
		{IP: "2001:db8::1", Port: 80, Protocol: "tcp"},
	}
	got := []string{}
	for _, b := range Batches(targets) {
		got = append(got, strings.Join(Args(b, Options{Extra: []string{"--version-intensity", "9"}}), " "))
	}
	want := []string{
		"-sT -sV -Pn -n -oX - -p 80,443 --version-intensity 9 10.0.0.1 10.0.0.2",
		"-sT -sV -Pn -n -oX - -sU -p T:22,U:53 --version-intensity 9 10.0.0.3",
		"-sT -sV -Pn -n -oX - -6 -p 80 --version-intensity 9 2001:db8::1",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

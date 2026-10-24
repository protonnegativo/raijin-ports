package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-ports",
		Findings: []Finding{{ID: "datastore-ab12cd34", Title: "Exposed datastore: Redis", Severity: "high", Tags: []string{"datastore"}, Service: Service{Protocol: "", Service: "redis"}, Locations: []string{"10.0.0.1:6379", "10.0.0.2:6379"}, Count: 2, Fingerprint: "fp"}},
		Groups:   []Group{{ID: "web-ef56ab78", Ports: []string{"80 http nginx"}, Locations: []string{"10.0.0.3"}, Count: 1}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "count", "confidence", "protocol", "product", "info", "state", "new", "omitted", "errors", "next", "raw", "budget"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
	if f, _ := json.Marshal(res.Findings[0]); strings.Contains(string(f), `"version"`) {
		t.Errorf("a finding without a version leaves it out: %s", f)
	}
}

func TestServiceFieldsAreInline(t *testing.T) {
	f := Finding{ID: "datastore-x", Title: "Exposed datastore: Redis key-value store", Severity: "high", Tags: []string{"datastore"}, Service: Service{Protocol: "udp", Service: "redis", Product: "Redis key-value store", Version: "7.0.11", Info: "standalone"}, Locations: []string{"10.0.0.1:6379"}}
	b, _ := json.Marshal(f)
	want := `{"id":"datastore-x","title":"Exposed datastore: Redis key-value store","severity":"high","tags":["datastore"],"protocol":"udp","service":"redis","product":"Redis key-value store","version":"7.0.11","info":"standalone","locations":["10.0.0.1:6379"]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "datastore-x", Tags: []string{"datastore"}, Locations: []string{"10.0.0.1:6379"}, Count: 7}},
		Groups:   []Group{{ID: "web-y", Ports: []string{"80 http"}, Count: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := json.Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"locations":["10.0.0.1:6379"],"count":7`) || !strings.Contains(s, `{"id":"web-y","ports":["80 http"],"count":4}`) {
		t.Errorf("count must be written when locations were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
}

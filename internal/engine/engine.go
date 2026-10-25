// Package engine knows the engine versions raijin-ports was tested with (engines.json) and checks the
// installed ones against them.
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	raijinports "github.com/protonnegativo/raijin-ports"
)

// Engine is one entry of engines.json: the tested version and where to install it from. Exactly one of
// Go (a module path), Pip or System (a package name) is set.
type Engine struct {
	Version string `json:"version"`
	Go      string `json:"go,omitempty"`
	Pip     string `json:"pip,omitempty"`
	System  string `json:"system,omitempty"`
}

// Tested parses the embedded engines.json.
func Tested() (map[string]Engine, error) {
	var m map[string]Engine
	if err := json.Unmarshal(raijinports.EnginesJSON, &m); err != nil {
		return nil, fmt.Errorf("engines.json: %w", err)
	}
	return m, nil
}

// Install is the command that installs version v of the engine.
func (e Engine) Install(v string) string {
	switch {
	case e.Go != "":
		return "go install " + e.Go + "@v" + v
	case e.Pip != "":
		return "pip install " + e.Pip + "==" + v
	default:
		return "install " + e.System + " " + v + " (apt install " + e.System + ", brew install " + e.System + ")"
	}
}

var versionRe = regexp.MustCompile(`v?(\d+)\.(\d+)(?:\.(\d+))?`)

// ParseVersion returns the first X.Y.Z or X.Y (with or without a leading v) in s: "2.6.1" from naabu's
// "Current Version: 2.6.1", "7.94" from "Nmap version 7.94SVN". ok is false when there is none.
func ParseVersion(s string) (v [3]int, text string, ok bool) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return v, "", false
	}
	for i := 0; i < 3; i++ {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	text = m[1] + "." + m[2]
	if m[3] != "" {
		text += "." + m[3]
	}
	return v, text, true
}

// Untested is true when installed is a different major version than tested, or older than tested.
// A newer minor or patch version of the same major is not: the weekly drift job tests those.
func Untested(installed, tested [3]int) bool {
	if installed[0] != tested[0] {
		return true
	}
	for i := 1; i < 3; i++ {
		if installed[i] != tested[i] {
			return installed[i] < tested[i]
		}
	}
	return false
}

// Check runs the engine's version command (3s timeout) and returns a hint when the installed version is
// untested, or "" when it is tested, newer in the same major, or could not be read.
func Check(ctx context.Context, name, bin string, args ...string) string {
	tested, err := Tested()
	if err != nil {
		return ""
	}
	e, found := tested[name]
	if !found {
		return ""
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	_ = cmd.Run()
	return hint(name, out.String(), e)
}

func hint(name, output string, e Engine) string {
	got, text, ok := ParseVersion(output)
	want, _, ok2 := ParseVersion(e.Version)
	if !ok || !ok2 || !Untested(got, want) {
		return ""
	}
	return fmt.Sprintf("%s %s is not the tested %s; results may be incomplete. Install the tested version: %s", name, text, e.Version, e.Install(e.Version))
}

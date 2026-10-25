// Package raijinports holds what the raijin-ports binary embeds from the repo root.
package raijinports

import _ "embed"

// EnginesJSON is engines.json: the engine versions the benchmark fixtures were produced with.
//
//go:embed engines.json
var EnginesJSON []byte

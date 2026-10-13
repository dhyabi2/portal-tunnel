package installer

import "strings"

func AssetFilename(slug string) (string, bool) {
	switch strings.TrimSpace(slug) {
	case "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64":
		return "portal-" + slug, true
	case "windows-amd64", "windows-arm64":
		return "portal-" + slug + ".exe", true
	case "js-wasm":
		return "portal-js-wasm.wasm", true
	case "wasm-exec":
		return "wasm_exec.js", true
	default:
		return "", false
	}
}

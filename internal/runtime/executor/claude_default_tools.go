package executor

import (
	_ "embed"
	"encoding/json"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

//go:embed claude_default_tools.json
var claudeDefaultToolsJSON []byte

// claudeDefaultToolsParsed is the pre-parsed default tools array.
// Initialized lazily on first use.
var claudeDefaultToolsParsed []json.RawMessage

func getDefaultTools() []json.RawMessage {
	if claudeDefaultToolsParsed != nil {
		return claudeDefaultToolsParsed
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(claudeDefaultToolsJSON, &tools); err != nil {
		return nil
	}
	claudeDefaultToolsParsed = tools
	return tools
}

// injectDefaultToolsIfMissing ensures the request has a tools array.
// Real Claude CLI always sends 22 built-in tools. Requests without tools
// are the single strongest proxy fingerprint. When cloaking, if the client
// didn't send any tools, inject the standard set.
func injectDefaultToolsIfMissing(payload []byte) []byte {
	existing := gjson.GetBytes(payload, "tools")

	// If tools already present and non-empty, leave as-is.
	if existing.Exists() && existing.IsArray() && len(existing.Array()) > 0 {
		return payload
	}

	tools := getDefaultTools()
	if tools == nil {
		return payload
	}

	result, err := sjson.SetRawBytes(payload, "tools", claudeDefaultToolsJSON)
	if err != nil {
		return payload
	}
	return result
}

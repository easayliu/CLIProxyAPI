package executor

import (
	_ "embed"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

//go:embed claude_system_prompt.txt
var claudeSystemPromptTemplate string

// modelDisplayNames maps model IDs to their display names as shown in Claude Code CLI.
var modelDisplayNames = map[string]string{
	"claude-opus-4-6":           "Opus 4.6 (with 1M context)",
	"claude-sonnet-4-6":         "Sonnet 4.6 (with 1M context)",
	"claude-haiku-4-5-20251001": "Haiku 4.5",
	"claude-sonnet-4-20250514":  "Sonnet 4 (with 200K context)",
}

// buildCLISystemPrompt generates the full Claude Code CLI system prompt
// with model-specific details substituted into the template.
func buildCLISystemPrompt(model string) string {
	display := modelDisplayNames[model]
	if display == "" {
		// Fallback: generate a reasonable display name from the model ID
		display = model
	}

	modelID := model
	// Real CLI appends context size suffix to the model ID
	if strings.Contains(display, "1M") {
		modelID = model + "[1m]"
	}

	prompt := claudeSystemPromptTemplate
	prompt = strings.ReplaceAll(prompt, "{{MODEL_DISPLAY}}", display)
	prompt = strings.ReplaceAll(prompt, "{{MODEL_ID}}", modelID)
	return prompt
}

// injectCLISystemPrompt inserts the Claude Code CLI system prompt as system[2]
// during cloaking. This makes the request indistinguishable from a real CLI request
// which always includes the full system prompt after the billing and agent blocks.
// In strict mode, only the CLI system prompt is kept (user system messages are dropped).
// In non-strict mode, the CLI system prompt is prepended before any user messages.
func injectCLISystemPrompt(payload []byte, model string, oauthMode, strictMode bool) []byte {
	system := gjson.GetBytes(payload, "system")
	if !system.Exists() || !system.IsArray() {
		return payload
	}

	blocks := system.Array()
	if len(blocks) < 2 {
		return payload // need at least billing + agent blocks
	}

	promptText := buildCLISystemPrompt(model)

	// Build the CLI system prompt block with appropriate cache_control
	cliBlock := `{"type":"text","cache_control":{"type":"ephemeral"}`
	if oauthMode {
		cliBlock = `{"type":"text","cache_control":{"type":"ephemeral","ttl":"1h"}`
	}
	// Use sjson to safely set the text field (handles JSON escaping)
	cliBlockJSON, _ := sjson.Set(cliBlock+"}", "text", promptText)

	// Rebuild system array: [billing, agent, cli-prompt, ...user-messages]
	billingBlock := blocks[0].Raw
	agentBlock := blocks[1].Raw

	if strictMode {
		// Strict mode: only billing + agent + CLI prompt
		result := "[" + billingBlock + "," + agentBlock + "," + cliBlockJSON + "]"
		payload, _ = sjson.SetRawBytes(payload, "system", []byte(result))
		return payload
	}

	// Non-strict mode: billing + agent + CLI prompt + existing user messages
	result := "[" + billingBlock + "," + agentBlock + "," + cliBlockJSON
	for i := 2; i < len(blocks); i++ {
		result += "," + blocks[i].Raw
	}
	result += "]"
	payload, _ = sjson.SetRawBytes(payload, "system", []byte(result))
	return payload
}

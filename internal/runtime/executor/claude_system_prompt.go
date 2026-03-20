package executor

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
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
// and migrates any extra system messages into the first user message content.
// Real Claude Code CLI always sends exactly 3 system blocks: billing, agent, and
// the full CLI system prompt. Any additional system messages from the client would
// be a detectable fingerprint. To preserve the client's custom instructions without
// breaking cloaking, extra system messages are wrapped in <system-reminder> tags
// and prepended to the first user message's content, matching how the real CLI
// handles CLAUDE.md and other injected context.
func injectCLISystemPrompt(payload []byte, model string, oauthMode bool) []byte {
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

	// Collect extra system messages (beyond billing + agent) for migration
	var extraTexts []string
	for i := 2; i < len(blocks); i++ {
		text := blocks[i].Get("text").String()
		if text != "" {
			extraTexts = append(extraTexts, text)
		}
	}

	// Rebuild system array: exactly 3 blocks (matching real CLI)
	billingBlock := blocks[0].Raw
	agentBlock := blocks[1].Raw
	result := "[" + billingBlock + "," + agentBlock + "," + cliBlockJSON + "]"
	payload, _ = sjson.SetRawBytes(payload, "system", []byte(result))

	// Migrate extra system messages into the first user message content
	if len(extraTexts) > 0 {
		payload = migrateSystemToUserMessage(payload, extraTexts)
	}

	return payload
}

// migrateSystemToUserMessage prepends extra system messages to the first user
// message's content array, wrapped in <system-reminder> tags to match real CLI behavior.
func migrateSystemToUserMessage(payload []byte, texts []string) []byte {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return payload
	}

	// Find the first user message
	for i, msg := range messages.Array() {
		if msg.Get("role").String() != "user" {
			continue
		}
		content := msg.Get("content")

		// Build reminder text block
		var combined string
		for _, t := range texts {
			// Skip if already wrapped in system-reminder
			if strings.Contains(t, "<system-reminder>") {
				combined += t + "\n"
			} else {
				combined += "<system-reminder>\n" + t + "\n</system-reminder>\n"
			}
		}

		reminderBlock := map[string]string{
			"type": "text",
			"text": combined,
		}
		reminderJSON, _ := json.Marshal(reminderBlock)

		if content.IsArray() {
			// Prepend to existing content array
			var newContent []interface{}
			newContent = append(newContent, json.RawMessage(reminderJSON))
			for _, block := range content.Array() {
				newContent = append(newContent, json.RawMessage(block.Raw))
			}
			path := fmt.Sprintf("messages.%d.content", i)
			payload, _ = sjson.SetBytes(payload, path, newContent)
		} else if content.Type == gjson.String {
			// Convert string content to array with reminder prepended
			var newContent []interface{}
			newContent = append(newContent, json.RawMessage(reminderJSON))
			textBlock := fmt.Sprintf(`{"type":"text","text":%s}`, strconv.Quote(content.String()))
			newContent = append(newContent, json.RawMessage(textBlock))
			path := fmt.Sprintf("messages.%d.content", i)
			payload, _ = sjson.SetBytes(payload, path, newContent)
		}
		break // only prepend to first user message
	}

	return payload
}

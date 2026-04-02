package executor

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

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

	// Build the CLI system prompt block with cache_control.
	// Real CLI uses {"scope":"global","ttl":"1h","type":"ephemeral"} for system[2].
	cliBlock := `{"type":"text","cache_control":{"scope":"global","ttl":"1h","type":"ephemeral"}}`
	// Prefix with \n to match real CLI behavior observed in MITM capture.
	cliBlockJSON, _ := sjson.Set(cliBlock, "text", "\n"+promptText)

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

	// Migrate extra system messages into the first user message content.
	// Always prepend default system-reminder blocks first, then append any
	// client extra system blocks. This ensures the first text block is always
	// the fixed defaultSkillsReminder, producing a consistent billing header
	// build hash (c8e) regardless of what the client sends.
	defaults := defaultSystemReminders()
	allTexts := append(defaults, extraTexts...)
	payload = migrateSystemToUserMessage(payload, allTexts)

	return payload
}

// defaultSkillsReminder is the standard skills list injected by real Claude Code CLI.
// Different users have different custom skills, but the built-in ones are always present.
// The content here matches a typical real CLI payload structure.
const defaultSkillsReminder = `<system-reminder>
The following deferred tools are now available via ToolSearch:
AskUserQuestion
CronCreate
CronDelete
CronList
EnterPlanMode
EnterWorktree
ExitPlanMode
ExitWorktree
NotebookEdit
RemoteTrigger
TaskCreate
TaskGet
TaskList
TaskOutput
TaskStop
TaskUpdate
WebFetch
WebSearch
mcp__ide__executeCode
mcp__ide__getDiagnostics
</system-reminder>`

// defaultSkillsAvailable is the standard skills available reminder from real CLI.
const defaultSkillsAvailable = `<system-reminder>
The following skills are available for use with the Skill tool:

- update-config: Use this skill to configure the Claude Code harness via settings.json. Automated behaviors ("from now on when X", "each time X", "whenever X", "before/after X") require hooks configured in settings.json - the harness executes these, not Claude, so memory/preferences cannot fulfill them. Also use for: permissions ("allow X", "add permission", "move permission to"), env vars ("set X=Y"), hook troubleshooting, or any changes to settings.json/settings.local.json files. Examples: "allow npm commands", "add bq permission to global settings", "move permission to user settings", "set DEBUG=true", "when claude stops show X". For simple settings like theme/model, use Config tool.
- keybindings-help: Use when the user wants to customize keyboard shortcuts, rebind keys, add chord bindings, or modify ~/.claude/keybindings.json. Examples: "rebind ctrl+s", "add a chord shortcut", "change the submit key", "customize keybindings".
- simplify: Review changed code for reuse, quality, and efficiency, then fix any issues found.
- loop: Run a prompt or slash command on a recurring interval (e.g. /loop 5m /foo, defaults to 10m) - When the user wants to set up a recurring task, poll for status, or run something repeatedly on an interval (e.g. "check the deploy every 5 minutes", "keep running /babysit-prs"). Do NOT invoke for one-off tasks.
- schedule: Create, update, list, or run scheduled remote agents (triggers) that execute on a cron schedule. - When the user wants to schedule a recurring remote agent, set up automated tasks, create a cron job for Claude Code, or manage their scheduled agents/triggers.
- claude-api: Build apps with the Claude API or Anthropic SDK.
TRIGGER when: code imports ` + "`anthropic`/`@anthropic-ai/sdk`/`claude_agent_sdk`" + `, or user asks to use Claude API, Anthropic SDKs, or Agent SDK.
DO NOT TRIGGER when: code imports ` + "`openai`" + `/other AI SDK, general programming, or ML/data-science tasks.
</system-reminder>`

// defaultSystemReminders generates the default system-reminder texts that
// real Claude Code CLI always injects into the first user message. These
// include the skills listing and the current date context.
func defaultSystemReminders() []string {
	dateReminder := fmt.Sprintf(`<system-reminder>
As you answer the user's questions, you can use the following context:
# currentDate
Today's date is %s.

      IMPORTANT: this context may or may not be relevant to your tasks. You should not respond to this context unless it is highly relevant to your task.
</system-reminder>`, time.Now().Format("2006-01-02"))

	return []string{
		defaultSkillsReminder,
		defaultSkillsAvailable,
		dateReminder,
	}
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
			// Prepend to existing content array, ensure last text block has cache_control.
			blocks := content.Array()
			var newContent []interface{}
			newContent = append(newContent, json.RawMessage(reminderJSON))
			for j, block := range blocks {
				raw := block.Raw
				// Last block: add cache_control if missing (matches CLI 2.1.90 behavior).
				if j == len(blocks)-1 && block.Get("type").String() == "text" && !block.Get("cache_control").Exists() {
					updated, err := sjson.SetRaw(raw, "cache_control", `{"ttl":"1h","type":"ephemeral"}`)
					if err == nil {
						raw = updated
					}
				}
				newContent = append(newContent, json.RawMessage(raw))
			}
			path := fmt.Sprintf("messages.%d.content", i)
			payload, _ = sjson.SetBytes(payload, path, newContent)
		} else if content.Type == gjson.String {
			// Convert string content to array with reminder prepended.
			// The user text block gets cache_control (matches CLI 2.1.90 behavior).
			var newContent []interface{}
			newContent = append(newContent, json.RawMessage(reminderJSON))
			textBlock := fmt.Sprintf(`{"type":"text","cache_control":{"ttl":"1h","type":"ephemeral"},"text":%s}`, strconv.Quote(content.String()))
			newContent = append(newContent, json.RawMessage(textBlock))
			path := fmt.Sprintf("messages.%d.content", i)
			payload, _ = sjson.SetBytes(payload, path, newContent)
		}
		break // only prepend to first user message
	}

	return payload
}

// Core CLI deferred tool names (without MCP tools which vary per user).
const cliDeferredToolsContent = "<available-deferred-tools>\nAgent\nAskUserQuestion\nBash\nCronCreate\nCronDelete\nCronList\nEdit\nEnterPlanMode\nEnterWorktree\nExitPlanMode\nExitWorktree\nGlob\nGrep\nNotebookEdit\nRead\nSkill\nTaskCreate\nTaskGet\nTaskList\nTaskOutput\nTaskStop\nTaskUpdate\nWebFetch\nWebSearch\nWrite\n</available-deferred-tools>"

// ToolSearch tool definition matching real Claude Code CLI v2.1.84.
var toolSearchDefinition = json.RawMessage(`{"name":"ToolSearch","description":"Fetches full schema definitions for deferred tools so they can be called.\n\nDeferred tools appear by name in <available-deferred-tools> messages. Until fetched, only the name is known \u2014 there is no parameter schema, so the tool cannot be invoked. This tool takes a query, matches it against the deferred tool list, and returns the matched tools' complete JSONSchema definitions inside a <functions> block. Once a tool's schema appears in that result, it is callable exactly like any tool defined at the top of the prompt.\n\nResult format: each matched tool appears as one <function>{\"description\": \"...\", \"name\": \"...\", \"parameters\": {...}}</function> line inside the <functions> block \u2014 the same encoding as the tool list at the top of this prompt.\n\nQuery forms:\n- \"select:Read,Edit,Grep\" \u2014 fetch these exact tools by name\n- \"notebook jupyter\" \u2014 keyword search, up to max_results best matches\n- \"+slack send\" \u2014 require \"slack\" in the name, rank by remaining terms","input_schema":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["query","max_results"],"additionalProperties":false,"properties":{"query":{"type":"string","description":"Query to find deferred tools. Use \"select:<tool_name>\" for direct selection, or keywords to search."},"max_results":{"type":"number","default":5,"description":"Maximum number of results to return (default: 5)"}}}}`)

// injectCLIDeferredTools prepends a deferred-tools user message and ensures
// the ToolSearch tool is present in the tools array. This matches real
// Claude Code CLI behavior where every request starts with the deferred
// tools listing and includes ToolSearch as the only always-loaded tool.
func injectCLIDeferredTools(payload []byte) []byte {
	// Check if deferred-tools message already exists (real CLI client)
	messages := gjson.GetBytes(payload, "messages")
	if messages.IsArray() && len(messages.Array()) > 0 {
		first := messages.Array()[0]
		if first.Get("role").String() == "user" {
			c := first.Get("content")
			if c.Type == gjson.String && strings.Contains(c.String(), "<available-deferred-tools>") {
				// Already has deferred tools — just ensure ToolSearch exists
				payload = ensureToolSearchInTools(payload)
				return payload
			}
		}
	}

	// Prepend deferred-tools user message
	deferredMsg := map[string]string{
		"role":    "user",
		"content": cliDeferredToolsContent,
	}
	deferredJSON, _ := json.Marshal(deferredMsg)

	if messages.IsArray() {
		var newMsgs []interface{}
		newMsgs = append(newMsgs, json.RawMessage(deferredJSON))
		for _, msg := range messages.Array() {
			newMsgs = append(newMsgs, json.RawMessage(msg.Raw))
		}
		payload, _ = sjson.SetBytes(payload, "messages", newMsgs)
	}

	payload = ensureToolSearchInTools(payload)
	return payload
}

// ensureToolSearchInTools adds ToolSearch to the tools array if not already present.
func ensureToolSearchInTools(payload []byte) []byte {
	tools := gjson.GetBytes(payload, "tools")

	// Check if ToolSearch already exists
	if tools.IsArray() {
		for _, tool := range tools.Array() {
			if tool.Get("name").String() == "ToolSearch" {
				return payload
			}
		}
		// Append to existing tools
		var newTools []interface{}
		for _, tool := range tools.Array() {
			newTools = append(newTools, json.RawMessage(tool.Raw))
		}
		newTools = append(newTools, toolSearchDefinition)
		payload, _ = sjson.SetBytes(payload, "tools", newTools)
	} else {
		// No tools array — create one with just ToolSearch
		payload, _ = sjson.SetBytes(payload, "tools", []json.RawMessage{toolSearchDefinition})
	}
	return payload
}

package claude

import (
	"strings"
	"testing"
)

func TestReorderAndLowercaseHeaders(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard headers lowercased",
			input: "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nX-Api-Key: sk-test\r\n\r\n{\"body\":true}",
			want:  "POST /v1/messages HTTP/1.1\r\nhost: api.anthropic.com\r\nx-api-key: sk-test\r\ncontent-type: application/json\r\n\r\n{\"body\":true}",
		},
		{
			name:  "reorders stainless headers to canonical order",
			input: "POST / HTTP/1.1\r\nUser-Agent: claude-cli/2.1.81\r\nX-Stainless-Lang: js\r\nAnthropic-Beta: claude-code-20250219\r\nX-Stainless-Runtime: node\r\nHost: api.anthropic.com\r\n\r\n",
			want:  "POST / HTTP/1.1\r\nhost: api.anthropic.com\r\nanthropic-beta: claude-code-20250219\r\nx-stainless-runtime: node\r\nx-stainless-lang: js\r\nuser-agent: claude-cli/2.1.81\r\n\r\n",
		},
		{
			name:  "already lowercase and ordered",
			input: "GET /test HTTP/1.1\r\nhost: example.com\r\n\r\n",
			want:  "GET /test HTTP/1.1\r\nhost: example.com\r\n\r\n",
		},
		{
			name:  "header value with uppercase preserved",
			input: "POST / HTTP/1.1\r\nAuthorization: Bearer SK-ANT-TOKEN\r\nContent-Type: Application/JSON\r\n\r\n",
			want:  "POST / HTTP/1.1\r\nauthorization: Bearer SK-ANT-TOKEN\r\ncontent-type: Application/JSON\r\n\r\n",
		},
		{
			name:  "body with colon not affected",
			input: "POST / HTTP/1.1\r\nHost: x\r\n\r\nKey: Value\r\nAnother: Header",
			want:  "POST / HTTP/1.1\r\nhost: x\r\n\r\nKey: Value\r\nAnother: Header",
		},
		{
			name:  "no headers",
			input: "GET / HTTP/1.1\r\n\r\n",
			want:  "GET / HTTP/1.1\r\n\r\n",
		},
		{
			name:  "unknown headers appended at end",
			input: "POST / HTTP/1.1\r\nX-Custom-Foo: bar\r\nHost: api.anthropic.com\r\nAccept: application/json\r\n\r\n",
			want:  "POST / HTTP/1.1\r\nhost: api.anthropic.com\r\naccept: application/json\r\nx-custom-foo: bar\r\n\r\n",
		},
		{
			name: "full realistic header set reordered",
			input: "POST /v1/messages HTTP/1.1\r\n" +
				"Accept: application/json\r\n" +
				"Accept-Encoding: gzip, deflate, br, zstd\r\n" +
				"Anthropic-Beta: claude-code-20250219\r\n" +
				"Anthropic-Version: 2023-06-01\r\n" +
				"Authorization: Bearer sk-test\r\n" +
				"Content-Length: 42\r\n" +
				"Content-Type: application/json\r\n" +
				"Host: api.anthropic.com\r\n" +
				"User-Agent: claude-cli/2.1.81\r\n" +
				"X-Api-Key: sk-test\r\n" +
				"X-Stainless-Lang: js\r\n" +
				"X-Stainless-Runtime: node\r\n" +
				"\r\n{\"test\":true}",
			want: "POST /v1/messages HTTP/1.1\r\n" +
				"host: api.anthropic.com\r\n" +
				"authorization: Bearer sk-test\r\n" +
				"x-api-key: sk-test\r\n" +
				"content-type: application/json\r\n" +
				"content-length: 42\r\n" +
				"anthropic-version: 2023-06-01\r\n" +
				"anthropic-beta: claude-code-20250219\r\n" +
				"x-stainless-runtime: node\r\n" +
				"x-stainless-lang: js\r\n" +
				"user-agent: claude-cli/2.1.81\r\n" +
				"accept: application/json\r\n" +
				"accept-encoding: gzip, deflate, br, zstd\r\n" +
				"\r\n{\"test\":true}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(reorderAndLowercaseHeaders([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("reorderAndLowercaseHeaders:\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestReorderAndLowercaseHeaders_OrderMatchesClaudeHeaderOrder(t *testing.T) {
	// Verify that output headers follow claudeHeaderOrder for known headers.
	input := "POST / HTTP/1.1\r\n" +
		"Connection: keep-alive\r\n" +
		"Accept-Encoding: gzip\r\n" +
		"Accept: application/json\r\n" +
		"User-Agent: test\r\n" +
		"X-Stainless-Os: linux\r\n" +
		"X-Stainless-Arch: x64\r\n" +
		"X-Stainless-Lang: js\r\n" +
		"X-Stainless-Runtime: node\r\n" +
		"X-Stainless-Package-Version: 1.0.0\r\n" +
		"X-Stainless-Runtime-Version: 18.0.0\r\n" +
		"X-Stainless-Retry-Count: 0\r\n" +
		"X-Stainless-Timeout: 60000\r\n" +
		"X-App: cli\r\n" +
		"Anthropic-Dangerous-Direct-Browser-Access: true\r\n" +
		"Anthropic-Beta: beta1\r\n" +
		"Anthropic-Version: 2023-06-01\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Length: 0\r\n" +
		"Content-Type: application/json\r\n" +
		"X-Api-Key: sk-test\r\n" +
		"Authorization: Bearer token\r\n" +
		"Host: api.anthropic.com\r\n" +
		"\r\n"

	result := string(reorderAndLowercaseHeaders([]byte(input)))

	// Extract header names from result.
	lines := strings.Split(result, "\r\n")
	var gotNames []string
	for i, line := range lines {
		if i == 0 {
			continue // skip request line
		}
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			gotNames = append(gotNames, parts[0])
		}
	}

	// All headers in this test are in claudeHeaderOrder, so the output
	// should exactly match that order.
	if len(gotNames) != len(claudeHeaderOrder) {
		t.Fatalf("header count = %d, want %d\ngot: %v", len(gotNames), len(claudeHeaderOrder), gotNames)
	}
	for i, want := range claudeHeaderOrder {
		if gotNames[i] != want {
			t.Errorf("header[%d] = %q, want %q\nfull order: %v", i, gotNames[i], want, gotNames)
		}
	}
}

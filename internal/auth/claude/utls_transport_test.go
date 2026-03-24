package claude

import (
	"testing"
)

func TestLowercaseRequestHeaders(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard headers",
			input: "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nX-Api-Key: sk-test\r\n\r\n{\"body\":true}",
			want:  "POST /v1/messages HTTP/1.1\r\nhost: api.anthropic.com\r\ncontent-type: application/json\r\nx-api-key: sk-test\r\n\r\n{\"body\":true}",
		},
		{
			name:  "mixed case stainless headers",
			input: "POST / HTTP/1.1\r\nX-Stainless-Lang: js\r\nX-Stainless-Runtime: node\r\nUser-Agent: claude-cli/2.1.81\r\nAnthropic-Beta: claude-code-20250219\r\n\r\n",
			want:  "POST / HTTP/1.1\r\nx-stainless-lang: js\r\nx-stainless-runtime: node\r\nuser-agent: claude-cli/2.1.81\r\nanthropic-beta: claude-code-20250219\r\n\r\n",
		},
		{
			name:  "already lowercase",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(tt.input)
			lowercaseRequestHeaders(raw)
			got := string(raw)
			if got != tt.want {
				t.Errorf("lowercaseRequestHeaders:\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

package model

import "strings"

const redactedValue = "[REDACTED]"

// RedactSensitive removes common credential arguments before events are
// evaluated or persisted. It is a narrow safeguard, not a general DLP system.
func RedactSensitive(event *Event) {
	if event == nil {
		return
	}
	if event.CommandLine != "" {
		event.CommandLine = redactCommandLine(event.CommandLine)
	}
	for key := range event.Fields {
		if sensitiveKey(key) {
			event.Fields[key] = redactedValue
		}
	}
}

func redactCommandLine(commandLine string) string {
	spans := commandTokens(commandLine)
	if len(spans) == 0 {
		return commandLine
	}
	var out strings.Builder
	out.Grow(len(commandLine))
	position := 0
	redactNext := false
	for _, span := range spans {
		out.WriteString(commandLine[position:span[0]])
		token := commandLine[span[0]:span[1]]
		if redactNext {
			out.WriteString(redactedValue)
			redactNext = false
		} else {
			key, delimiter, found := sensitiveArgument(token)
			if key && found {
				out.WriteString(token[:delimiter+1])
				out.WriteString(redactedValue)
			} else {
				out.WriteString(token)
				redactNext = key && !found
			}
		}
		position = span[1]
	}
	out.WriteString(commandLine[position:])
	return out.String()
}

func commandTokens(value string) [][2]int {
	var spans [][2]int
	start := -1
	quoted := false
	for index := 0; index < len(value); index++ {
		char := value[index]
		if start < 0 && !isSpace(char) {
			start = index
		}
		if char == '"' {
			backslashes := 0
			for previous := index - 1; previous >= 0 && value[previous] == '\\'; previous-- {
				backslashes++
			}
			if backslashes%2 == 0 {
				quoted = !quoted
			}
		}
		if isSpace(char) && !quoted && start >= 0 {
			spans = append(spans, [2]int{start, index})
			start = -1
		}
	}
	if start >= 0 {
		spans = append(spans, [2]int{start, len(value)})
	}
	return spans
}

func isSpace(value byte) bool { return value == ' ' || value == '\t' || value == '\r' || value == '\n' }

func sensitiveArgument(token string) (bool, int, bool) {
	trimmed := strings.Trim(token, "\"'")
	tokenOffset := strings.Index(token, trimmed)
	argument := strings.TrimLeft(trimmed, "-\\/")
	argumentOffset := len(trimmed) - len(argument)
	if delimiter := strings.IndexAny(argument, "=:"); delimiter >= 0 {
		return sensitiveKey(argument[:delimiter]), tokenOffset + argumentOffset + delimiter, true
	}
	return sensitiveKey(argument), 0, false
}

func sensitiveKey(value string) bool {
	key := strings.ToLower(strings.TrimSpace(value))
	key = strings.Trim(key, "\"'")
	key = strings.NewReplacer("_", "-", " ", "-").Replace(key)
	key = strings.TrimLeft(key, "-\\/")
	for _, suffix := range []string{"-password", "-passwd", "-pwd", "-token", "-secret", "-api-key", "-apikey", "-credential", "-authorization"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	switch key {
	case "password", "passwd", "pwd", "token", "access-token", "refresh-token", "client-secret", "secret", "api-key", "apikey", "credential", "authorization":
		return true
	default:
		return false
	}
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type logLevel int

const (
	levelTrace logLevel = iota
	levelDebug
	levelInfo
	levelWarn
	levelError
)

func parseLogLevel(value string) logLevel {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "TRACE":
		return levelTrace
	case "DEBUG":
		return levelDebug
	case "INFO":
		return levelInfo
	case "WARN", "WARNING":
		return levelWarn
	case "ERROR":
		return levelError
	default:
		return levelInfo
	}
}

func (level logLevel) String() string {
	switch level {
	case levelTrace:
		return "TRACE"
	case levelDebug:
		return "DEBUG"
	case levelWarn:
		return "WARN"
	case levelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

type logFormat int

const (
	logFormatText logFormat = iota
	logFormatJSON
)

func parseLogFormat(value string) logFormat {
	if strings.EqualFold(strings.TrimSpace(value), "json") {
		return logFormatJSON
	}
	return logFormatText
}

func (format logFormat) String() string {
	if format == logFormatJSON {
		return "json"
	}
	return "text"
}

type logField struct {
	key   string
	value any
}

func field(key string, value any) logField {
	return logField{key: key, value: value}
}

type logger struct {
	level  logLevel
	format logFormat
	output *log.Logger
}

type redisLogger struct {
	logger logger
}

func (l redisLogger) Printf(_ context.Context, format string, args ...interface{}) {
	l.logger.Event(levelError, "redis_client", field("message", fmt.Sprintf(format, args...)))
}

func newLogger(levelValue, formatValue string) logger {
	return newLoggerWithWriter(parseLogLevel(levelValue), parseLogFormat(formatValue), os.Stdout)
}

func newLoggerWithWriter(level logLevel, format logFormat, output io.Writer) logger {
	flags := log.LstdFlags
	if format == logFormatJSON {
		flags = 0
	}
	return logger{
		level:  level,
		format: format,
		output: log.New(output, "", flags),
	}
}

func (l logger) Tracef(format string, args ...any) {
	l.logf(levelTrace, format, args...)
}

func (l logger) Debugf(format string, args ...any) {
	l.logf(levelDebug, format, args...)
}

func (l logger) Infof(format string, args ...any) {
	l.logf(levelInfo, format, args...)
}

func (l logger) Warnf(format string, args ...any) {
	l.logf(levelWarn, format, args...)
}

func (l logger) Errorf(format string, args ...any) {
	l.logf(levelError, format, args...)
}

func (l logger) Event(level logLevel, event string, fields ...logField) {
	if l.level > level {
		return
	}

	if l.format == logFormatJSON {
		entry := map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
			"level":     level.String(),
			"event":     event,
		}
		for _, item := range fields {
			entry[item.key] = normalizeLogValue(item.value)
		}
		raw, err := json.Marshal(entry)
		if err != nil {
			l.printer().Printf(`{"timestamp":%q,"level":"ERROR","event":"log_encode_error","error":%q}`, time.Now().UTC().Format(time.RFC3339Nano), err.Error())
			return
		}
		l.printer().Print(string(raw))
		return
	}

	var message strings.Builder
	message.WriteString("[")
	message.WriteString(level.String())
	message.WriteString("] event=")
	message.WriteString(formatLogValue(event))
	for _, item := range fields {
		message.WriteByte(' ')
		message.WriteString(item.key)
		message.WriteByte('=')
		message.WriteString(formatLogValue(normalizeLogValue(item.value)))
	}
	l.printer().Print(message.String())
}

func (l logger) logf(level logLevel, format string, args ...any) {
	if l.level > level {
		return
	}
	message := fmt.Sprintf(format, args...)
	if l.format == logFormatJSON {
		entry := map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
			"level":     level.String(),
			"event":     "log",
			"message":   message,
		}
		raw, err := json.Marshal(entry)
		if err == nil {
			l.printer().Print(string(raw))
		}
		return
	}
	l.printer().Printf("[%s] %s", level.String(), message)
}

func (l logger) printer() *log.Logger {
	if l.output != nil {
		return l.output
	}
	return log.Default()
}

func formatLogValue(value any) string {
	text := fmt.Sprint(value)
	if text == "" || strings.ContainsAny(text, " \t\r\n\"=") {
		return strconv.Quote(text)
	}
	return text
}

func normalizeLogValue(value any) any {
	switch typed := value.(type) {
	case error:
		return typed.Error()
	case logLevel:
		return typed.String()
	case logFormat:
		return typed.String()
	default:
		return value
	}
}

package logger

import (
	"fmt"
	"io"
	"log"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
)

// LogRecorder is a callback that stores events in an external datastore.
type LogRecorder func(le *LogEntry) error

// Logger captures interaction event logs for the honeypot to determine its
// performance.
type Logger struct {
	Record LogRecorder
}

// NewJsonLinesLogRecorder creates a Logger that exports logs in newline
// delimited JSON object format.
func NewJsonLinesLogRecorder(w io.Writer) *Logger {
	return &Logger{
		Record: func(le *LogEntry) error {
			entry, err := protojson.Marshal(le)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(w, string(entry))
			return err
		},
	}
}

func (l *Logger) recordLogType(sessionID string, event isLogEntry_LogType) error {
	le := &LogEntry{}
	le.TimestampMicros = time.Now().UnixMicro()
	le.SessionId = sessionID
	le.LogType = event

	return l.Record(le)
}

// NewSession creates a logger with attached session ID.
func (l *Logger) NewSession(sessionID string) *SessionLogger {
	return &SessionLogger{Logger: l, sessionID: sessionID}
}

// NewSession creates a logger with attached session ID.
func (l *Logger) Sessionless() *SessionLogger {
	return &SessionLogger{Logger: l, sessionID: ""}
}

// SessionLogger logs messages with a shared session ID.
type SessionLogger struct {
	*Logger
	sessionID string
}

type LogType = isLogEntry_LogType

func (l *SessionLogger) Record(event LogType) error {
	return l.recordLogType(l.sessionID, event)
}

func (l *SessionLogger) Print(event LogType) error {
	log.Println("evetnt:", event)

	return nil
}

func (l *SessionLogger) SessionID() string {
	return l.sessionID
}

/*
 * @Description:
 * @Version: 2.0
 * @Autor: ABing
 * @Date: 2024-06-28 12:49:20
 * @LastEditors: lhl
 * @LastEditTime: 2024-07-02 14:45:29
 */
package jsonlog

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strconv"

	"sync"
	"time"
)

var GlobalLog *Logger

func Init() {
	GlobalLog = &Logger{LogFile: "log/ssh/ssh.json"}
}

type Logger struct {
	LogFile string
	mu      sync.Mutex
}

type LogEntry struct {
	Type                string         `json:"type"`
	Timestamp           int64          `json:"timestamp"`
	Protocol            string         `json:"protocol"`
	App                 string         `json:"app"`
	Name                string         `json:"name"`
	UUID                string         `json:"UUID"`
	DestPort            int            `json:"dest_port,omitempty"`
	SrcIP               string         `json:"src_ip,omitempty"`
	SrcPort             int            `json:"src_port,omitempty"`
	Request             string         `json:"request,omitempty"`
	DestIP              string         `json:"dest_ip,omitempty"`
	Payload             string         `json:"payload,omitempty"`
	DeobfuscatedPayload string         `json:"deobfuscated_payload,omitempty"`
	Exception           string         `json:"exception,omitempty"`
	Extend              map[string]any `json:"extend,omitempty"`
}

func (l *Logger) Log(entry LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.Timestamp = time.Now().UnixNano() / int64(time.Millisecond)

	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("Failed to marshal log entry: %v", err)
		return
	}

	f, err := os.OpenFile(l.LogFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.Write(append(data, '\n')); err != nil {
		log.Printf("Failed to write to log file: %v", err)
	}
}

func (l *Logger) HoneyLog(LocalAddr, RemoteAddr string, atype string, extend map[string]any) {

	DestIP, DestPort, _ := net.SplitHostPort(LocalAddr)
	DestPortInt, _ := strconv.Atoi(DestPort)

	clientIP, clientPort, _ := net.SplitHostPort(RemoteAddr)
	portInt, _ := strconv.Atoi(clientPort)

	currentTime := time.Now()
	milliseconds := currentTime.UnixNano() / int64(time.Millisecond)

	log := LogEntry{
		Type:      atype,
		DestIP:    DestIP,
		DestPort:  DestPortInt,
		SrcIP:     clientIP,
		SrcPort:   portInt,
		Extend:    extend,
		UUID:      "<UUID>",
		App:       "ssh",
		Name:      "ssh",
		Protocol:  "ssh",
		Timestamp: milliseconds,
	}

	l.Log(log)
}

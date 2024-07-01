package main

import (
	"github.com/josephlewis42/honeyssh/jsonlog"

	"github.com/josephlewis42/honeyssh/cmd"
)

func main() {
	jsonlog.Init()
	cmd.Execute()
}

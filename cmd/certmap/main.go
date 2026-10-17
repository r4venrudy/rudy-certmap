package main

import (
	"github.com/r4venrudy/rudy-certmap/internal/cli"
	"os"
	"time"
)

func main() { os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, time.Now)) }

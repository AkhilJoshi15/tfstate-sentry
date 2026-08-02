package main

import (
	"os"

	"github.com/AkhilJoshi15/tfstate-sentry/internal/app"
)

func main() {
	os.Exit(app.Run(os.Args[1:], os.Stdout, os.Stderr))
}

// Package main provides killswitch-user, the graphical-session companion daemon
// for killswitch desktop integration such as user-visible notifications.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configPath, err := parseArgs(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	opts, err := loadOptions(configPath, os.Getenv)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, opts, newDesktopNotifier()); err != nil {
		log.Fatal(err)
	}
}

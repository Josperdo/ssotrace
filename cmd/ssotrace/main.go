// Command ssotrace diagnoses failed SSO logins from a HAR file.
//
// This file only wires the process to internal/cli: everything testable
// lives there, because os.Exit and os.Args are hard to test.
package main

import (
	"os"
	"runtime/debug"

	"github.com/Josperdo/ssotrace/internal/cli"
)

// Set at link time by the Makefile:
//
//	-ldflags "-X main.version=... -X main.commit=... -X main.date=..."
//
// They stay empty for `go install` and `go run` builds; buildInfo fills them
// in from the metadata the Go toolchain embeds in every binary.
var (
	version string
	commit  string
	date    string
)

func main() {
	v, c, d := buildInfo()
	info := cli.BuildInfo{Version: v, Commit: c, Date: d}
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, info))
}

// buildInfo returns the ldflags values when present and otherwise falls back
// to the module version and VCS stamps recorded by the Go toolchain.
func buildInfo() (v, c, d string) {
	v, c, d = version, commit, date

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return orUnknown(v), orUnknown(c), orUnknown(d)
	}
	if v == "" {
		v = bi.Main.Version // "v1.2.3" for `go install ...@v1.2.3`, "(devel)" for local builds
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if c == "" {
				c = s.Value
			}
		case "vcs.time":
			if d == "" {
				d = s.Value
			}
		}
	}
	return orUnknown(v), orUnknown(c), orUnknown(d)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

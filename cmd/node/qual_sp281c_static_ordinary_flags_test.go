package main

import (
	"testing"

	"github.com/urfave/cli"
)

func TestQualSP281CStaticOrdinaryFlags(t *testing.T) {
	var displayCount, colorCount int
	for _, flag := range getFlags() {
		switch flag.GetName() {
		case "display-name":
			displayCount++
			value, ok := flag.(cli.StringFlag)
			if !ok || value.Value != "" || value.Usage == "" {
				t.Fatalf("ordinary display-name metadata differs: %v", flag)
			}
		case "disable-ansi-color":
			colorCount++
			value, ok := flag.(cli.BoolFlag)
			if !ok || value.Usage == "" {
				t.Fatalf("ordinary ANSI-color metadata differs: %v", flag)
			}
		}
	}
	if displayCount != 1 || colorCount != 1 {
		t.Fatalf("expected one ordinary declaration each; display=%d color=%d", displayCount, colorCount)
	}
}

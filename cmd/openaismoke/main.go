// Command openaismoke performs one explicitly enabled, non-mutating OpenAI
// contract check. It never persists analysis, approves policy, or reaches an
// enforcement component.
package main

import (
	"context"
	"os"
)

func main() {
	exitCode := runCLI(context.Background(), os.Stdout, os.Stderr, productionDependencies())
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

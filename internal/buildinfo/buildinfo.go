// Package buildinfo exposes the immutable identity shared by SentinelFlow
// command entry points. Release builds may replace Version through -ldflags.
package buildinfo

const Name = "SentinelFlow"

// Version is a variable so release builds can replace it with -ldflags -X.
var Version = "dev"

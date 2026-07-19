// Package executor orchestrates SentinelFlow's isolated, once-only nftables
// execution boundary.
//
// The package deliberately does not open sockets, select database work, or
// interpret model output. IPC framing is handled by package ipc, exact signed
// artifacts by package capability, and durable replay authority by package
// journal. A Runner receives only closed, fixed-command value types; it is the
// later OS adapter's responsibility to invoke the absolute nft binary directly
// without a shell or environment-selected PATH.
package executor

// Package nftbootstrap owns the executor-only nftables base-chain boundary.
//
// Bootstrap is deliberately separate from normal readiness checks. It accepts
// only the byte-exact pinned base-chain contract, requires an empty network
// namespace, applies that contract once through a fixed nft invocation, and
// then proves the resulting kernel structure. VerifyLive is read-only and
// projects the current owned table into the separately pinned canonical live
// schema. Neither operation accepts a binary path, command-line arguments, or
// shell input from its caller.
package nftbootstrap

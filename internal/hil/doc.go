// Package hil implements the pure, exact-artifact administrator decision
// boundary. It creates immutable RFC 8785/JCS-compatible challenge, reason,
// and decision artifacts, and it provides an in-process single-use guard that
// mirrors the compare-and-set operation required from a future durable store.
//
// This package does not authenticate HTTP requests, persist records, mint
// executor capabilities, invoke nftables, or implement the revocation
// authorization flow. It only validates the frozen revocation wire branches.
// A durable adapter must atomically persist decision/challenge consumption;
// an approval or revocation value alone never grants execution authority.
package hil

// Package nftcheck implements the isolated, pre-HIL nftables syntax gate.
//
// It accepts only bounded canonical candidate bytes whose SHA-256 digest is
// supplied independently, verifies the byte-exact pinned owned base contract,
// and asks a narrowly scoped process runner to execute nft --check -f -.
// Successful validation is not execution authority and does not mutate an
// nftables ruleset.
package nftcheck

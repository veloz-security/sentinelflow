// Package nftvalidate independently validates the closed nft-blacklist-v1
// command language and the pinned SentinelFlow-owned nftables schema.
//
// It is deliberately pure: it never starts a process, opens a socket, invokes
// nft, or passes data to a shell. A successful Result is therefore only an
// input to the later isolated nft --check gate; it is not execution authority.
package nftvalidate

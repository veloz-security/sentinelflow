// Package nftrunner provides the Linux-only, fixed-command nftables process
// adapter for the isolated SentinelFlow executor.
//
// The production adapter can execute only two invocations: an exact mutation
// through /usr/sbin/nft -f - and a read-only JSON listing of the owned IPv4
// timeout set. It never invokes a shell, consults PATH, or exposes process
// output through errors.
package nftrunner

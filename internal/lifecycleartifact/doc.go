// Package lifecycleartifact constructs and parses SentinelFlow's immutable,
// database-independent lifecycle artifacts.
//
// The package deliberately exposes no generic nftables command builder. It
// supports only the frozen read-only nft-inspect-v1 artifact, its separate
// non-HIL inspection-authorization-v1 authority, and the exact single-target
// nft-revoke-v1 delete artifact.
package lifecycleartifact

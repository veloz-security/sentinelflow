// Package lifecycleruntime prepares due read-only lifecycle inspections.
//
// It is deliberately not a persistence or execution authority. A Store owns
// DB-clocked due selection, lease fencing, atomic commit, and exact replay.
// This runtime can only construct checked nft-inspect-v1 and
// inspection-authorization-v1 values; it has no mutation, HIL, dispatcher, or
// executor surface.
package lifecycleruntime

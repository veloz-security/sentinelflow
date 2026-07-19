// Package journal implements the executor's append-only, fsync-backed replay
// journal. It records an exact signed capability before a mutation and an exact
// signed result after invocation and read-back.
//
// A recovered started-only entry is deliberately not executable. It may be
// used to bind and sign a read-back recovery result, but it never releases nft
// mutation bytes. Corrupt or incomplete journals fail closed and are never
// truncated or repaired by this package.
package journal

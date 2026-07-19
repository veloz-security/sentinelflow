// Package executorserver owns the executor's private Unix-domain listener.
//
// It deliberately delegates byte framing and the one-request/one-response
// exchange to package ipc, and delegates authorization, journaling, nftables,
// and result signing to package executor. This package exposes no TCP listener,
// peer-selected command, database connection, or secret-bearing diagnostic.
package executorserver

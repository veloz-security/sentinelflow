// Package events owns SentinelFlow's minimized v1 event wire contracts.
//
// Decoders in this package are intentionally strict. They return typed values
// only after rejecting unknown or duplicate fields, trailing JSON, invalid
// formats, and fields that would violate the event privacy allowlist. Neither
// decoded values nor validation errors retain arbitrary input fields or raw
// event JSON.
package events

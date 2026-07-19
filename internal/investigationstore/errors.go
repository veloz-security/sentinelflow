package investigationstore

import "errors"

var (
	// ErrInvalidArgument is safe to translate to a generic client error. It
	// never includes the rejected value.
	ErrInvalidArgument = errors.New("investigation store: invalid argument")
	// ErrNotFound deliberately does not distinguish a missing resource from a
	// resource that the caller is not entitled to discover.
	ErrNotFound = errors.New("investigation store: resource not found")
	// ErrUnavailable hides all driver, SQL, topology, and persisted-data detail.
	ErrUnavailable = errors.New("investigation store: unavailable")
	// ErrInvalidRow means a database row violated the frozen read contract. It
	// is not safe to return the row or the underlying scan error to a client.
	ErrInvalidRow = errors.New("investigation store: invalid row")
)

package config

import "fmt"

// Error contains only a variable name and a fixed diagnostic. It never wraps
// parser errors because standard parser errors may echo credential values.
type Error struct {
	Field   string
	Problem string
}

func (e *Error) Error() string {
	return fmt.Sprintf("configuration %s: %s", e.Field, e.Problem)
}

func configError(field, problem string) error {
	return &Error{Field: field, Problem: problem}
}

// Package dispatchstore implements the least-privilege PostgreSQL boundary for
// SentinelFlow's non-AI dispatcher. It can see only approved exact-artifact
// jobs and can mutate dispatch state only through fenced SECURITY DEFINER
// functions.
package dispatchstore

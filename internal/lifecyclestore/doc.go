// Package lifecyclestore persists read-only enforcement lifecycle inspections.
//
// Its PostgreSQL role can execute only three SECURITY DEFINER functions. The
// adapter never receives administrator HIL material, executor authority,
// mutation bytes, a signing key, or direct table privileges.
package lifecyclestore

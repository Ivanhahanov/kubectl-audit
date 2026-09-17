// Package migrations embeds the SQL files golang-migrate applies against
// Postgres. Kept as its own package (not internal/storage/postgres
// itself) purely because go:embed requires the directive to live in the
// same directory as the embedded files.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS

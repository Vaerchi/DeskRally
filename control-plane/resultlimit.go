package controlplane

import (
	"errors"
	"net/http"
)

// Until the list APIs support cursors, refuse oversized results rather than return a
// silently incomplete fleet/report or materialize an unbounded tenant history.
const maxListRows = 10000

var ErrQueryTooBroad = errors.New("query exceeds the 10000-row result limit")

func appendListRow[T any](rows *[]T, row T) error {
	if len(*rows) >= maxListRows {
		return ErrQueryTooBroad
	}
	*rows = append(*rows, row)
	return nil
}

func writeListError(w http.ResponseWriter, err error, fallback string) {
	if errors.Is(err, ErrQueryTooBroad) {
		writeError(w, http.StatusUnprocessableEntity, "query exceeds the 10000-row result limit; narrow the date range where available; no partial results returned")
		return
	}
	writeError(w, http.StatusInternalServerError, fallback)
}

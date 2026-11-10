//go:build !acceptance

package main

import (
	"io"
	"net/http"
)

const buildFlavor = "production"

// install 在产品构建里什么都不装。
func install(handler http.Handler, serverLog io.Writer, _ seams) (http.Handler, io.Writer, error) {
	return handler, serverLog, nil
}

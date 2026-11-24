//go:build !unix

package filestate

import (
	"context"
	"errors"
)

// Hold 在非 unix 平台没有 flock。
func (s *Store) Hold(context.Context) (func(), error) {
	return nil, errors.New("fabric state: file locks are only available on unix")
}

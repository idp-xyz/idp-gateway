//go:build !unix

package history

func setUmask(mask int) int { return mask }

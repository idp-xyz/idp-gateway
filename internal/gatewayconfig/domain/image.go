package domain

import (
	"fmt"
	"strings"
)

// ImageReference 报告 reference 是不是按摘要引用的镜像：仓库名、@sha256:、64 位小写十六进制。
// 按标签引用的（仓库:标签）不是。离线加载和换镜像用的是同一条规则。
func ImageReference(reference string) error {
	repository, digest, found := strings.Cut(reference, "@sha256:")
	if !found || repository == "" || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
		return fmt.Errorf("image %q is not referenced by digest (repository@sha256:…)", reference)
	}
	return nil
}

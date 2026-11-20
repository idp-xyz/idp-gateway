// Package sbom 写出本模块的 CycloneDX 1.6 文档。
//
// 组件只有调用方交给它的模块，和 Go 标准库的版本。go.mod 里没有 require 的模块不写包地址。
// 这里不描述 agentgateway 的镜像，也不拉取镜像。
package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Document 把模块和 Go 标准库编成一份 CycloneDX 1.6 JSON。
// moduleVersion 为空就省略：主模块在本仓库里没有版本号，不另造一个。
// stdlibVersion 用 `go version` 报出的那一截，例如 go1.26.8。
// 返回的字节以换行结束。
func Document(modulePath, moduleVersion, stdlibVersion string) ([]byte, error) {
	if modulePath == "" || strings.ContainsAny(modulePath, " \t\r\n") {
		return nil, errors.New("sbom: module path is empty")
	}
	if stdlibVersion == "" || strings.ContainsAny(stdlibVersion, " \t\r\n") {
		return nil, errors.New("sbom: stdlib version is empty")
	}
	if strings.ContainsAny(moduleVersion, "\r\n") {
		return nil, errors.New("sbom: module version is not a single line")
	}
	module := component{
		Type:    "application",
		Name:    modulePath,
		Version: moduleVersion,
	}
	doc := bom{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: metadata{
			Component: module,
		},
		Components: []component{
			module,
			{
				Type:    "library",
				Name:    "stdlib",
				Version: stdlibVersion,
			},
		},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ParseGoVersion 从 `go version` 的整行里取出版本。
// 正式发布是 go1.26.8 这种一个词；开发版中间可以有空格，操作系统和架构留在最后一截。
func ParseGoVersion(output string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) < 4 || fields[0] != "go" || fields[1] != "version" || !strings.Contains(fields[len(fields)-1], "/") {
		return "", fmt.Errorf("sbom: cannot read go version from %q", strings.TrimSpace(output))
	}
	return strings.Join(fields[2:len(fields)-1], " "), nil
}

type bom struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    metadata    `json:"metadata"`
	Components  []component `json:"components"`
}

type metadata struct {
	Component component `json:"component"`
}

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// ComponentNames 返回文档里写了名字的组件：根组件，和 components 里的每一项。
func ComponentNames(doc []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	var parsed bom
	if err := dec.Decode(&parsed); err != nil {
		return nil, errors.New("sbom: document is not CycloneDX JSON")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("sbom: document has trailing data")
	}
	names := make([]string, 0, 1+len(parsed.Components))
	if parsed.Metadata.Component.Name != "" {
		names = append(names, parsed.Metadata.Component.Name)
	}
	for _, item := range parsed.Components {
		if item.Name == "" {
			return nil, errors.New("sbom: component name is empty")
		}
		names = append(names, item.Name)
	}
	return names, nil
}

// MissingRequires 返回 go.mod 的 require 里没有出现在文档组件名中的模块路径。
func MissingRequires(doc, goMod []byte) ([]string, error) {
	required, err := Requires(goMod)
	if err != nil {
		return nil, err
	}
	names, err := ComponentNames(doc)
	if err != nil {
		return nil, err
	}
	have := make(map[string]struct{}, len(names))
	for _, name := range names {
		have[name] = struct{}{}
	}
	var missing []string
	for _, path := range required {
		if _, ok := have[path]; !ok {
			missing = append(missing, path)
		}
	}
	return missing, nil
}

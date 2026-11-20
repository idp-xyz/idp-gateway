package sbom

import (
	"bytes"
	"strings"
	"testing"
)

func TestDocumentOmitsVersionAndPurlWhenModuleHasNone(t *testing.T) {
	raw, err := Document("go.idp.xyz/idp-gateway", "", "go1.26.8")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("文档应以换行结束")
	}
	if bytes.Contains(raw, []byte("purl")) || bytes.Contains(raw, []byte("pkg:golang")) {
		t.Fatalf("没有 require 的模块不写包地址：\n%s", raw)
	}
	names, err := ComponentNames(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"go.idp.xyz/idp-gateway", "go.idp.xyz/idp-gateway", "stdlib"}
	if strings.Join(names, ",") != strings.Join(wantNames, ",") {
		t.Fatalf("组件名是 %v", names)
	}
	if bytes.Contains(raw, []byte(`"version": "go.idp.xyz/idp-gateway"`)) {
		t.Fatal("主模块没有版本")
	}
	if !bytes.Contains(raw, []byte(`"version": "go1.26.8"`)) {
		t.Fatalf("标准库版本没有写入：\n%s", raw)
	}
	if !bytes.Contains(raw, []byte(`"specVersion": "1.6"`)) || !bytes.Contains(raw, []byte(`"bomFormat": "CycloneDX"`)) {
		t.Fatalf("不是 CycloneDX 1.6：\n%s", raw)
	}
}

func TestDocumentKeepsModuleVersion(t *testing.T) {
	raw, err := Document("example.com/mod", "v1.2.3", "go1.26.8")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"name": "example.com/mod"`)) || !bytes.Contains(raw, []byte(`"version": "v1.2.3"`)) {
		t.Fatalf("模块版本没有写入：\n%s", raw)
	}
	if bytes.Contains(raw, []byte("purl")) {
		t.Fatal("这份生成器不写包地址")
	}
}

func TestDocumentRejectsBlankInput(t *testing.T) {
	if _, err := Document("", "", "go1.26.8"); err == nil {
		t.Fatal("空模块路径应拒绝")
	}
	if _, err := Document("go.idp.xyz/idp-gateway", "", ""); err == nil {
		t.Fatal("空标准库版本应拒绝")
	}
	if _, err := Document("go.idp.xyz/idp-gateway", "", "go 1.26.8"); err == nil {
		t.Fatal("带空格的标准库版本应拒绝")
	}
}

func TestParseGoVersion(t *testing.T) {
	got, err := ParseGoVersion("go version go1.26.8 linux/amd64\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "go1.26.8" {
		t.Fatalf("版本是 %q", got)
	}
	got, err = ParseGoVersion("go version devel go1.27-abcdef linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got != "devel go1.27-abcdef" {
		t.Fatalf("开发版是 %q", got)
	}
	if _, err := ParseGoVersion("go1.26.8"); err == nil {
		t.Fatal("残缺的输出应拒绝")
	}
}

func TestRequires(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "本模块这样的文件",
			in:   "module go.idp.xyz/idp-gateway\n\ngo 1.26.0\n\ntoolchain go1.26.5\n",
		},
		{
			name: "括号里的 require",
			in:   "module m\n\ngo 1.26.0\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.2.3 // indirect\n)\n",
			want: "example.com/a,example.com/b",
		},
		{
			name: "单行 require",
			in:   "module m\n\ngo 1.26.0\n\nrequire example.com/c v0.1.0\n",
			want: "example.com/c",
		},
		{
			name: "replace 和 exclude 不是 require",
			in:   "module m\n\ngo 1.26.0\n\nreplace example.com/d => example.com/e v1.0.0\nexclude example.com/f v1.2.3\n",
		},
		{
			name: "引号和注释",
			in:   "module \"require\"\n\ngo 1.26.0\n\n// require example.com/nope v1.0.0\n/*\nrequire example.com/hidden v1.0.0\n*/\nrequire \"example.com/g\" v1.0.0\n",
			want: "example.com/g",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Requires([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, ",") != tc.want {
				t.Fatalf("得到 %v，要 %s", got, tc.want)
			}
		})
	}
}

func TestMissingRequires(t *testing.T) {
	doc, err := Document("go.idp.xyz/idp-gateway", "", "go1.26.8")
	if err != nil {
		t.Fatal(err)
	}
	missing, err := MissingRequires(doc, []byte("module go.idp.xyz/idp-gateway\n\ngo 1.26.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("没有 require 时不应缺组件：%v", missing)
	}
	missing, err = MissingRequires(doc, []byte("module m\n\ngo 1.26.0\n\nrequire example.com/absent v1.0.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(missing, ",") != "example.com/absent" {
		t.Fatalf("缺的是 %v", missing)
	}
}

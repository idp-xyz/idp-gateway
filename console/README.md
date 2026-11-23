# 控制台页面

这是给 `gateway-console` 用的页面。构建之后由同一个进程在回环上提供，浏览器访问的地址和 `/v1` 是同一个来源。

```bash
cd console
npm ci
npm run build
cd ..
go build -o /tmp/gateway-console ./cmd/gateway-console
/tmp/gateway-console --listen 127.0.0.1:19100 --audit-log /path/audit.jsonl --ui console/dist
```

不给 `--ui` 时只有接口，没有页面。页面不发布路由，也不回滚。撤销和封禁仍要五个证书参数；不给时页面上会看到 `revoker is not configured`。

`npm run dev` 把 `/v1` 转到 `127.0.0.1:19100`，只给本机改页面时用。

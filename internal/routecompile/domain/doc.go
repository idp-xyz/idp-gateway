// Package domain 把中立的 RouteIntent 预检，以及把已批准的出站意图编译成
// agentgateway 配置和 gateway-authz 登记表的规则，放在一起。
//
// 本包不做 I/O，不跑网关二进制，也不读文件。预检在默认情况下与
// scripts/preflight_intents.py 一样严格；编译期的明文沙箱和同池签名器例外
// 只在 CompileOptions 里打开，预检不带这些选项。
package domain

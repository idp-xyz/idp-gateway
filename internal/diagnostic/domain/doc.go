// Package domain 是离线诊断参照的纯规则，从 scripts/diagnostic_reference.py 移植。
//
// 本包不做 I/O，不导入 net、os、log。它不采集正文，也不是抓包工具。
// 四阶段只用契约里已有的名字，这里没有声称在运行的网关上观察过它们。
package domain

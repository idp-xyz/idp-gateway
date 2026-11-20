package domain

import "strings"

// isIPLiteral 判断主机名是不是 IP 字面量。domain 不能导入 net，这里按
// ipaddress.ip_address 的口径认 IPv4 和 IPv6：四段十进制、不允许前导零；
// IPv6 允许一次 ::，末段可以是 IPv4。
func isIPLiteral(host string) bool {
	if host == "" {
		return false
	}
	if parseIPv4(host) {
		return true
	}
	return parseIPv6(host)
}

func parseIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 3 {
			return false
		}
		if len(part) > 1 && part[0] == '0' {
			return false
		}
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func parseIPv6(s string) bool {
	if s == "" || strings.Contains(s, "%") || !strings.Contains(s, ":") {
		return false
	}
	if strings.Count(s, "::") > 1 {
		return false
	}
	head, tail, compressed := strings.Cut(s, "::")
	var groups []string
	if !compressed {
		groups = strings.Split(s, ":")
	} else {
		if head != "" {
			groups = append(groups, strings.Split(head, ":")...)
		}
		if tail != "" {
			groups = append(groups, strings.Split(tail, ":")...)
		}
	}
	count := len(groups)
	if count > 0 && strings.Contains(groups[count-1], ".") {
		if !parseIPv4(groups[count-1]) {
			return false
		}
		groups = groups[:count-1]
		count = len(groups) + 2
	}
	for _, group := range groups {
		if !hexGroup(group) {
			return false
		}
	}
	if compressed {
		return count < 8
	}
	return count == 8
}

func hexGroup(s string) bool {
	if s == "" || len(s) > 4 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

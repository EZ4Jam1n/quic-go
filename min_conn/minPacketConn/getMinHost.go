package minPacketConn

import "strings"

func GetMinHost(addr string) string {
	indexByte := strings.Index(addr, "/port/")
	if indexByte == -1 {
		return addr
	} else {
		return addr[0:indexByte]
	}
}

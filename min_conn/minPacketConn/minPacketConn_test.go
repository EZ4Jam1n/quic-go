package minPacketConn

import (
	"fmt"
	"github.com/quic-go/quic-go/min_conn"
	"testing"
	"time"
)

func TestMINPacketConn(t *testing.T) {
	var conn1 MINPacketConn
	conn1.DebugInitWithSocket()
	var conn2 MINPacketConn
	conn2.DebugInitWithSocket()
	var data []byte = []byte{1, 3, 4, 5, 6, 7, 78, 4}
	var rdata []byte = make([]byte, 100)
	go func() {
		time.Sleep(2 * time.Second)
		a, err := conn1.WriteTo(data, min_conn.NewMinPushAddr("/minPushAddr"))
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(a)
	}()
	go func() {
		conn2.SetReadDeadline(time.Now().Add(4 * time.Second))
		a, b, err := conn2.ReadFrom(rdata)
		fmt.Println("data from:", b.String())
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(a)
		fmt.Println(rdata)
	}()
	for {
		time.Sleep(10 * time.Second)
	}
}

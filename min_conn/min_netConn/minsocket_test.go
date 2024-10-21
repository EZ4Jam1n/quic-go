package min_netConn

import (
	"fmt"
	"testing"
	"time"
)

func TestMINConn(t *testing.T) {
	var conn1 MINConn
	conn1.DebugInitWithSocket()
	var conn2 MINConn
	conn2.DebugInitWithSocket()
	var data []byte = []byte{1, 3, 4, 5, 6, 7, 78, 4}
	var rdata []byte = make([]byte, 100)
	go func() {
		time.Sleep(2 * time.Second)
		a, err := conn1.Write(data)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(a)
	}()
	go func() {
		conn2.SetReadDeadline(time.Now().Add(4 * time.Second))
		a, err := conn2.Read(rdata)
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

func TestReceive(t *testing.T) {
	var conn2 MINConn
	conn2.DebugInitWithSocket()
	var rdata []byte = make([]byte, 1000)
	for {
		conn2.SetReadDeadline(time.Now().Add(4 * time.Second))
		a, err := conn2.Read(rdata)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(a)
		fmt.Println(rdata)
	}
}

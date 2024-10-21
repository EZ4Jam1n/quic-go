// Package min_netConn
// implement net.Conn interface for MIN
package min_netConn

import (
	"github.com/quic-go/quic-go/min_conn"
	"minlib/common"
	"minlib/component"
	"minlib/logicface"
	"minlib/packet"
	"net"
	"time"
)

type MINConn struct {
	logicFace     *logicface.LogicFace
	localAddr     min_conn.MinPushAddr
	remoteAddr    min_conn.MinPushAddr
	deadLine      time.Time
	readDeadLine  time.Time
	writeDeadLine time.Time
}

func (m *MINConn) LocalAddr() net.Addr {
	return &m.localAddr
}

func (m *MINConn) RemoteAddr() net.Addr {
	return &m.remoteAddr
}

func (m *MINConn) SetDeadline(t time.Time) error {
	m.deadLine = t
	return nil
}

func (m *MINConn) SetReadDeadline(t time.Time) error {
	m.readDeadLine = t
	return nil
}

func (m *MINConn) SetWriteDeadline(t time.Time) error {
	m.writeDeadLine = t
	return nil
}

func (m *MINConn) Write(b []byte) (n int, err error) {
	//set local and remote address for MIN GPPkt
	srcIdentifier, err := component.CreateIdentifierByString(m.LocalAddr().String())
	if err != nil {
		common.LogFatal(err)
		return 0, err
	}
	dstIdentifier, err := component.CreateIdentifierByString(m.RemoteAddr().String())
	if err != nil {
		common.LogFatal(err)
		return 0, err
	}
	gPPkt := new(packet.GPPkt)
	gPPkt.SetSrcIdentifier(srcIdentifier)
	gPPkt.SetTTL(64)
	gPPkt.SetDstIdentifier(dstIdentifier)
	gPPkt.SetValue(b)
	err = m.logicFace.SendGPPkt(gPPkt)
	if err != nil {
		common.LogFatal("Sending GPPkt failed", err.Error())
		return 0, err
	}
	return len(b), nil
}

func (m *MINConn) Read(b []byte) (n int, err error) {
	pkt, err := m.logicFace.ReceiveGPPkt((m.readDeadLine.Unix() - time.Now().Unix()) * 1000)
	if err != nil {
		//common.LogFatal(err)
		common.LogWarn(err)
		return 0, err
	}
	tmp := pkt.Payload.GetValue()
	return copy(b, tmp), nil
}

func (m *MINConn) Close() error {
	return m.logicFace.Shutdown()
}

func (m *MINConn) DebugInitWithSocket() error {
	m.localAddr = *min_conn.NewMinPushAddr("/minPushAddr1")
	m.remoteAddr = *min_conn.NewMinPushAddr("/minPushAddr")
	m.logicFace = new(logicface.LogicFace)
	if err := m.logicFace.InitWithUnixSocket("/tmp/mir.sock"); err != nil {
		common.LogFatal(err)
		return err
	}
	identifier, err := component.CreateIdentifierByString(m.LocalAddr().String())
	if err != nil {
		common.LogFatal(err)
		return err
	}
	if err := m.logicFace.RegisterPushIdentifier(identifier, -1); err != nil {
		common.LogFatal(err)
	}
	return nil
}

func (m *MINConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	pkt, err := m.logicFace.ReceiveGPPkt((m.readDeadLine.Unix() - time.Now().Unix()) * 1000)
	if err != nil {
		common.LogFatal(err)
		return 0, min_conn.NewMinPushAddr(""), err
	}
	tmp := pkt.Payload.GetValue()

	return copy(p, tmp), min_conn.NewMinPushAddr("/" + pkt.SrcIdentifier().ToUri()), nil
}
func (m *MINConn) WriteTo(p []byte, addr min_conn.MinPushAddr) (n int, err error) {
	//set local and remote address for MIN GPPkt
	srcIdentifier, err := component.CreateIdentifierByString(m.LocalAddr().String())
	if err != nil {
		common.LogFatal(err)
		return 0, err
	}
	dstIdentifier, err := component.CreateIdentifierByString("/" + addr.String())
	if err != nil {
		common.LogFatal(err)
		return 0, err
	}
	gPPkt := new(packet.GPPkt)
	gPPkt.SetSrcIdentifier(srcIdentifier)
	gPPkt.SetTTL(64)
	gPPkt.SetDstIdentifier(dstIdentifier)
	gPPkt.SetValue(p)
	err = m.logicFace.SendGPPkt(gPPkt)
	if err != nil {
		common.LogFatal("Sending GPPkt failed", err.Error())
		return 0, err
	}
	return len(p), nil
}

/*

SyscallConn() (syscall.RawConn, error)
*/

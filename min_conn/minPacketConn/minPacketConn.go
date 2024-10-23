package minPacketConn

import (
	"errors"
	"fmt"
	"net"
	"path"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/quic-go/quic-go/min_conn"
	"minlib/common"
	"minlib/component"
	"minlib/logicface"
	"minlib/minsecurity/identity"
	"minlib/packet"
	"minlib/security"
)

var connConf ConnConf

const (
	MINConn_TCP   = "tcp"
	MINConn_UDP   = "udp"
	MINConn_Unix  = "unix"
	MINConn_Ether = "ether"
)

// TODO 封装成包
func init() {
	var abPath string
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		abPath = path.Dir(filename)
	}
	if _, err := toml.DecodeFile(abPath+"/../config.toml", &connConf); err != nil {
		common.LogError(err)
	}
	fmt.Println(connConf)
}

const (
	SignOption_NotSigned        = 0
	SignOption_SignedWithDB     = 1
	SignOption_SignedWithIdFile = 2
)

type MINConfig struct {
	RemoteMINAddr string
	LocalMINAddr  string
	SignOption    int
	Identity      string
	PassWord      string
	DbPath        string
	IdFilePath    string
	IdFilePwd     string
}

type MINPacketConn struct {
	logicFace     *logicface.LogicFace
	localAddr     min_conn.MinPushAddr
	remoteAddr    min_conn.MinPushAddr
	deadLine      time.Time
	readDeadLine  time.Time
	writeDeadLine time.Time
	isSign        bool
	keyChain      *security.KeyChain
}

func (m *MINPacketConn) LocalAddr() net.Addr {
	return &m.localAddr
}

func (m *MINPacketConn) RemoteAddr() net.Addr {
	return &m.remoteAddr
}

func (m *MINPacketConn) SetDeadline(t time.Time) error {
	m.deadLine = t
	return nil
}

func (m *MINPacketConn) SetReadDeadline(t time.Time) error {
	m.readDeadLine = t
	return nil
}

func (m *MINPacketConn) SetWriteDeadline(t time.Time) error {
	m.writeDeadLine = t
	return nil
}

func (m *MINPacketConn) Close() error {
	return m.logicFace.Shutdown()
}

func (m *MINPacketConn) DebugInitWithSocket() error {
	m.localAddr = *min_conn.NewMinPushAddr("/minPushAddr")
	m.remoteAddr = *min_conn.NewMinPushAddr("/minPushAddr")
	m.logicFace = new(logicface.LogicFace)

	switch connConf.ConnType.Name {
	case MINConn_Unix:
		if err := m.logicFace.InitWithUnixSocket(connConf.UnixConn.Addr); err != nil {
			common.LogError(err)
			return err
		}
	case MINConn_TCP:
		if err := m.logicFace.InitWithTcp(connConf.TcpConn.Ip, connConf.TcpConn.Port); err != nil {
			common.LogError(err)
			return err
		}
	case MINConn_UDP:
		if err := m.logicFace.InitWithUdp(connConf.UdpConn.Ip, connConf.UdpConn.Port); err != nil {
			common.LogError(err)
			return err
		}
	case MINConn_Ether:
		if err := m.logicFace.InitWithEthernet(connConf.EtherConn.IfName, connConf.EtherConn.LocalMacAddr, connConf.EtherConn.RemoteMacAddr); err != nil {
			common.LogError(err)
			return err
		}
	default:
		err := errors.New("未知的连接类型" + connConf.ConnType.Name)
		return err
	}
	identifier, err := component.CreateIdentifierByString(m.LocalAddr().String())
	if err != nil {
		common.LogError(err)
		return err
	}
	if err := m.logicFace.RegisterPushIdentifier(identifier, -1); err != nil {
		common.LogError(err)
		return err
	}
	return nil
}

func (m *MINPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	pkt, err := m.logicFace.ReceiveGPPkt((m.readDeadLine.Unix() - time.Now().Unix()) * 1000)
	if err != nil {
		common.LogWarn("read err", err)
		return 0, min_conn.NewMinPushAddr(""), err
	}
	tmp := pkt.Payload.GetValue()
	return copy(p, tmp), min_conn.NewMinPushAddr(pkt.SrcIdentifier().ToUri()), nil
}

func (m *MINPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	//set local and remote address for MIN GPPkt
	/*
		srcIdentifier, err := component.CreateIdentifierByString("/" + m.LocalAddr().String())
		if err != nil {
			common.LogFatal(err)
			return 0, err
		}
		dstIdentifier, err := component.CreateIdentifierByString("/" + addr.String())
		if err != nil {
			common.LogFatal(err)
			return 0, err
		}
	*/
	//	fmt.Println(p)
	srcIdentifier, err := component.CreateIdentifierByString(m.LocalAddr().String())
	if err != nil {
		common.LogWarn("write err", err)
		return 0, err
	}
	dstIdentifier, err := component.CreateIdentifierByString(addr.String())
	if err != nil {
		common.LogWarn(err)
		return 0, err
	}

	gPPkt := new(packet.GPPkt)
	gPPkt.SetSrcIdentifier(srcIdentifier)
	gPPkt.SetTTL(64)
	gPPkt.SetDstIdentifier(dstIdentifier)
	gPPkt.SetValue(p)
	if m.isSign {
		err := m.keyChain.SignGPPkt(gPPkt)
		if err != nil {
			common.LogWarn(err)
			return 0, err
		}
	}

	err = m.logicFace.SendGPPkt(gPPkt)
	if err != nil {
		common.LogError("Sending GPPkt failed", err.Error())
		return 0, err
	}
	return len(p), nil
}

func NewMINPacketConn_UDPSend(minConfig *MINConfig) (*MINPacketConn, error) {
	minpConn := &MINPacketConn{}
	minpConn.remoteAddr = *min_conn.NewMinPushAddr(minConfig.RemoteMINAddr)
	minpConn.localAddr = *min_conn.NewMinPushAddr(minConfig.LocalMINAddr)
	minpConn.logicFace = new(logicface.LogicFace)

	switch connConf.ConnType.Name {
	case MINConn_Unix:
		if err := minpConn.logicFace.InitWithUnixSocket(connConf.UnixConn.Addr); err != nil {
			common.LogError(err)
			return minpConn, err
		}
	case MINConn_TCP:
		if err := minpConn.logicFace.InitWithTcp(connConf.TcpConn.Ip, connConf.TcpConn.Port); err != nil {
			common.LogError(err)
			return minpConn, err
		}
	case MINConn_UDP:
		if err := minpConn.logicFace.InitWithUdp(connConf.UdpConn.Ip, connConf.UdpConn.Port); err != nil {
			common.LogError(err)
			return minpConn, err
		}
	case MINConn_Ether:
		if err := minpConn.logicFace.InitWithEthernet(connConf.EtherConn.IfName, connConf.EtherConn.LocalMacAddr, connConf.EtherConn.RemoteMacAddr); err != nil {
			common.LogError(err)
			return minpConn, err
		}
	default:
		err := errors.New("未知的连接类型" + connConf.ConnType.Name)
		return minpConn, err
	}
	identifier, err := component.CreateIdentifierByString(minpConn.LocalAddr().String())
	if err != nil {
		common.LogError(err)
		return minpConn, err
	}
	if err := minpConn.logicFace.RegisterPushIdentifier(identifier, -1); err != nil {
		common.LogError(err)
		return minpConn, err
	}
	switch minConfig.SignOption {
	case SignOption_NotSigned:
	case SignOption_SignedWithDB:
		minpConn.isSign = true
		var err error
		minpConn.keyChain, err = security.NewKeyChainByIdentityName(minConfig.Identity, minConfig.PassWord, minConfig.DbPath)
		if err != nil {
			common.LogError(err)
			return minpConn, err
		}
	case SignOption_SignedWithIdFile:
		minpConn.isSign = true
		var err1 error
		var id *identity.Identity
		id, err1 = LoadIdentidy(minConfig.IdFilePath, minConfig.IdFilePwd)
		if err1 != nil {
			common.LogError(err1)
			return minpConn, err1
		}
		var keyChain security.KeyChain
		if err := keyChain.SetCurrentIdentity(id, minConfig.PassWord); err != nil {
			common.LogError(err)
			return minpConn, err
		}
		keyChain.IdentityManager.InitInnerMap()
		// 因为身份是从数据库中取出来的，所以这里就不需要再次进行持久化了，第二个参数填为false
		keyChain.IdentityManager.AddIdentity(id, false)
		minpConn.keyChain = &keyChain
	}
	return minpConn, nil
}

func NewMINPacketConn_UDPListen(minConfig *MINConfig) (*MINPacketConn, error) {
	minpConn := &MINPacketConn{}
	minpConn.localAddr = *min_conn.NewMinPushAddr(minConfig.LocalMINAddr)
	minpConn.logicFace = new(logicface.LogicFace)
	switch connConf.ConnType.Name {
	case MINConn_Unix:
		if err := minpConn.logicFace.InitWithUnixSocket(connConf.UnixConn.Addr); err != nil {
			common.LogError(err)
			return minpConn, err
		}
	case MINConn_TCP:
		if err := minpConn.logicFace.InitWithTcp(connConf.TcpConn.Ip, connConf.TcpConn.Port); err != nil {
			common.LogError(err)
			return minpConn, err
		}
	case MINConn_UDP:
		if err := minpConn.logicFace.InitWithUdp(connConf.UdpConn.Ip, connConf.UdpConn.Port); err != nil {
			common.LogError("init with udp err:" + err.Error())
			return minpConn, err
		}
	case MINConn_Ether:
		if err := minpConn.logicFace.InitWithEthernet(connConf.EtherConn.IfName, connConf.EtherConn.LocalMacAddr, connConf.EtherConn.RemoteMacAddr); err != nil {
			common.LogError("init with ether err:" + err.Error())
			return minpConn, err
		}
	default:
		err := errors.New("未知的连接类型" + connConf.ConnType.Name)
		return minpConn, err
	}
	identifier, err := component.CreateIdentifierByString(minpConn.LocalAddr().String())
	if err != nil {
		common.LogError(err)
		return minpConn, err
	}
	if err := minpConn.logicFace.RegisterPushIdentifier(identifier, -1); err != nil {
		common.LogError(err)
		return minpConn, err
	}
	switch minConfig.SignOption {
	case SignOption_NotSigned:
	case SignOption_SignedWithDB:
		minpConn.isSign = true
		var err error
		minpConn.keyChain, err = security.NewKeyChainByIdentityName(minConfig.Identity, minConfig.PassWord, minConfig.DbPath)
		if err != nil {
			common.LogError(err)
			return minpConn, err
		}
	case SignOption_SignedWithIdFile:
		minpConn.isSign = true
		var err1 error
		var id *identity.Identity
		id, err1 = LoadIdentidy(minConfig.IdFilePath, minConfig.IdFilePwd)
		if err1 != nil {
			common.LogError(err1)
			return minpConn, err1
		}
		var keyChain security.KeyChain
		if err := keyChain.SetCurrentIdentity(id, minConfig.PassWord); err != nil {
			common.LogError(err)
			return minpConn, err
		}
		keyChain.IdentityManager.InitInnerMap()
		// 因为身份是从数据库中取出来的，所以这里就不需要再次进行持久化了，第二个参数填为false
		keyChain.IdentityManager.AddIdentity(id, false)
		minpConn.keyChain = &keyChain
	}

	return minpConn, nil
}

type TcpConn struct {
	Ip   string
	Port int
}

type UdpConn struct {
	Ip   string
	Port int
}

type UnixConn struct {
	Addr string
}

type ConnType struct {
	Name string
}

type EtherConn struct {
	IfName        string
	LocalMacAddr  net.HardwareAddr
	RemoteMacAddr net.HardwareAddr
}

type ConnConf struct {
	ConnType  ConnType
	TcpConn   TcpConn
	UdpConn   UdpConn
	UnixConn  UnixConn
	EtherConn EtherConn
}

func SetMIRConn(c ConnConf) {
	connConf = c
	fmt.Println("reset minConn")
	fmt.Println(connConf)
}

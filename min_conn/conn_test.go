package min_conn

import (
	"minlib/common"
	"minlib/component"
	_ "minlib/encoding"
	"minlib/logicface"
	_ "minlib/mgmt"
	"minlib/packet"
	"minlib/utils"
	"testing"
)

func TestLogicFace_ReceivePacket(t *testing.T) {
	lf := new(logicface.LogicFace)
	if err := lf.InitWithUnixSocket("/tmp/mir.sock"); err != nil {
		common.LogFatal(err)
	}
	identifier, err := component.CreateIdentifierByString("/pkusz")
	if err != nil {
		common.LogFatal(err)
	}

	//if err := lf.RegisterPullIdentifier(identifier, -1, new(mgmt.RegisterPrefixHelper)); err != nil {
	if err := lf.RegisterPushIdentifier(identifier, -1); err != nil {
		common.LogFatal(err)
	}

	var cnt int = 0
	for true {
		pkt, err := lf.ReceiveGPPkt(-1)
		if err != nil {
			common.LogFatal(err)
		}
		_, err = pkt.GetIdentifier(0)
		if err != nil {
			common.LogFatal(err)
		}

		cnt++
		common.LogInfo("received GPPkt:", cnt)
		/*
			if id.GetIdentifierType() == encoding.TlvIdentifierCommon {
				common.LogInfo("received GPPkt:", cnt)
			} else if id.GetIdentifierType() == encoding.TlvIdentifierContentInterest {
				common.LogInfo("received Interest Packet:", cnt)
			} else if id.GetIdentifierType() == encoding.TlvIdentifierContentData {
				common.LogInfo("received Data Packet:", cnt)
			}
		*/

	}
}

func TestLogicFace_InitWithUnixSocket(t *testing.T) {
	var logicFace logicface.LogicFace
	err := logicFace.InitWithUnixSocket("/tmp/mir.sock")
	if err != nil {
		t.Fatal("Init logicface with Unix Socket failed", err.Error())
	}

	sendGPPkt(&logicFace, t)
}

func sendGPPkt(logicFace *logicface.LogicFace, t *testing.T) {
	identifier, err := component.CreateIdentifierByString("/pkusz")
	if err != nil {
		common.LogFatal(err)
	}
	gPPkt := new(packet.GPPkt)
	gPPkt.SetSrcIdentifier(identifier)
	gPPkt.SetTTL(64)
	gPPkt.SetValue(utils.RandomBytes(8000))
	gPPkt.SetDstIdentifier(identifier)
	var packetNum int = 100000
	startTime := utils.GetTimestampMS()
	for i := 0; i < packetNum; i++ {
		err = logicFace.SendGPPkt(gPPkt)
		if err != nil {
			t.Fatal("Sending GPPkt failed", err.Error())
		}
	}
	spanTime := utils.GetTimestampMS() - startTime
	common.LogInfo("speed: ", float64(packetNum)*1.3*8.0/float64(spanTime)*1.0, "Mbps")
}

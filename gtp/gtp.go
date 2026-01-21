package gtp
import (
	"fmt"
	"github.com/google/gopacket"
	// "github.com/google/gopacket/layers"
	// "github.com/google/gopacket/pcap"
)

type GtpHeader struct {
	Version	uint8
	P_Flag	bool
	T_Flag	bool
	Mp_Flag	bool

	MsgType	uint8
	MsgLen	uint16

	Teid	uint32
	SeqNum 	uint32

	mp 		uint8
}

func GtpParse(payload gopacket.Payload) {

	version := uint8( (payload[0] >>5) & 0x07)
	p_Flag := ((payload[0]>>4) & 0x01) == 1
	T_Flag := ((payload[0]>>3) & 0x01) == 1
	Mp_Flag := ((payload[0]>>2) & 0x01) == 1

	MsgType := payload[1]
	MsgLen :=  uint16(payload[2])<<8 | uint16(payload[3])

	var Teid uint32
	if (T_Flag){
		Teid =  uint32(payload[4]) << 16 |
				uint32(payload[5]) << 8 |
				uint32(payload[6])
	} else  {
		Teid = 0
	}

	SeqNum :=  0
	mp :=      0

	gtpHeader := GtpHeader{
		Version: version,
		P_Flag: p_Flag,
		T_Flag: T_Flag,
		Mp_Flag: Mp_Flag,
		MsgType: MsgType,
		MsgLen: MsgLen,
		Teid: Teid,
		SeqNum: uint32(SeqNum),
		mp: uint8(mp),
	}
	fmt.Println(gtpHeader)
}
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

import (
	_ "github.com/google/gopacket/layers"
)

const (
	defaultSnapLen = 262144
)

func parseMCC(data []byte) string {
	mccA1 := data[21] & 0xF
	mccA2 := (data[21] & 0xF0) >> 4
	mccA3 := data[22] & 0x0F
	mccArray := []byte{mccA1, mccA2, mccA3}
	return fmt.Sprintf("%d%d%d", mccArray[0], mccArray[1], mccArray[2])
}

func parseMNC(data []byte) string {
	mncA1 := data[23] & 0x0F
	mncA2 := (data[23] & 0xF0) >> 4
	mncA3 := (data[22] & 0xF0) >> 4
	mncArray := []byte{mncA1, mncA2, mncA3}
	if mncArray[2] == 15 {
		return fmt.Sprintf("%d%d", mncArray[0], mncArray[1])
	}
	return fmt.Sprintf("%d%d%d", mncArray[0], mncArray[1], mncArray[2])
}

func parseLAC(data []byte) string {
	return hex.EncodeToString(data[24:][:2])
}

func main() {
	handle, err := pcap.OpenLive("lo", defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("port 4729"); err != nil {
		panic(err)
	}

	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {
		payload_data := pkt.Layer(layers.LayerTypeUDP).LayerPayload()

		//System Information Type 3
		if payload_data[18] == 27 {
			//CI
			//fmt.Print(parseMCC(payload_data))
			//fmt.Print(parseMNC(payload_data))
			//ciHex := hex.EncodeToString(payload_data[19:][:2])
			//ciDecimal, _ := strconv.ParseInt(ciHex, 16, 32)
			mcc := parseMCC(payload_data)
			mnc := parseMNC(payload_data)
			lac := parseLAC(payload_data)
			fmt.Print("MCC : " + mcc + " MNC : " + mnc + " LAC : " + lac + "\n")
		}
		if payload_data[18] == 33 {

			if payload_data[21]&0x7 == 0 { //No Identity
			}
			if payload_data[21]&0x7 == 1 { //IMSI

				mncA2 := (payload_data[23] & 0xF0) >> 4
				fmt.Print(mncA2)
				encodedString := hex.EncodeToString(payload_data[22:][:7])
				data := fmt.Sprintf("IMSI: %d (0x%s)\n", payload_data[22:][:7], encodedString)
				fmt.Print(data)
			}
			if payload_data[21]&0x7 == 2 { //IMEI

			}
			if payload_data[21]&0x7 == 3 { //IMEISV

			}
			if payload_data[21]&0x7 == 4 { //TMSI/P-TMSI/M-TMSI
				encodedString := hex.EncodeToString(payload_data[22:][:4])
				data := fmt.Sprintf("TMSI/P-TMSI/M-TMSI/5G-TMSI: %d (0x%s)\n", payload_data[22:][:4], encodedString)
				fmt.Print(data)
			}
			if payload_data[21]&0x7 == 5 { //TMGI and optional MBMS Session Identity

			}

		}

	}
}

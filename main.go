package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

var espressifPrefixList = `782184	78-21-84
1097BD	10-97-BD
30C6F7	30-C6-F7
24D7EB	24-D7-EB
70B8F6	70-B8-F6
485519	48-55-19
E89F6D	E8-9F-6D
D4F98D	D4-F9-8D
4CEBD6	4C-EB-D6
349454	34-94-54
686725	68-67-25
58CF79	58-CF-79
1091A8	10-91-A8
90380C	90-38-0C
58BF25	58-BF-25
7C87CE	7C-87-CE
943CC6	94-3C-C6
6055F9	60-55-F9
409151	40-91-51
308398	30-83-98
1C9DC2	1C-9D-C2
AC0BFB	AC-0B-FB
84F703	84-F7-03
34865D	34-86-5D
78E36D	78-E3-6D
98CDAC	98-CD-AC
9C9C1F	9C-9C-1F
4C7525	4C-75-25
441793	44-17-93
EC94CB	EC-94-CB
A4E57C	A4-E5-7C
8C4B14	8C-4B-14
C8C9A3	C8-C9-A3
34B472	34-B4-72
A848FA	A8-48-FA
34AB95	34-AB-95
BCFF4D	BC-FF-4D
C45BBE	C4-5B-BE
545AA6	54-5A-A6
2C3AE8	2C-3A-E8
ECFABC	EC-FA-BC
DC4F22	DC-4F-22
B4E62D	B4-E6-2D
3C71BF	3C-71-BF
2CF432	2C-F4-32
4C11AE	4C-11-AE
B8F009	B8-F0-09
7C9EBD	7C-9E-BD
F008D1	F0-08-D1
483FDA	48-3F-DA
18FE34	18-FE-34
A47B9D	A4-7B-9D
84F3EB	84-F3-EB
840D8E	84-0D-8E
C82B96	C8-2B-96
84CCA8	84-CC-A8
40F520	40-F5-20
10521C	10-52-1C
F4CFA2	F4-CF-A2
E09806	E0-98-06
30AEA4	30-AE-A4
C44F33	C4-4F-33
D8F15B	D8-F1-5B
AC67B2	AC-67-B2
7CDFA1	7C-DF-A1
8CAAB5	8C-AA-B5
5CCF7F	5C-CF-7F
A020A6	A0-20-A6
24B2DE	24-B2-DE
D8A01D	D8-A0-1D
BCDDC2	BC-DD-C2
CC50E3	CC-50-E3
A4CF12	A4-CF-12
2462AB	24-62-AB
500291	50-02-91
D8BFC0	D8-BF-C0
98F4AB	98-F4-AB
70039F	70-03-9F
FCF5C4	FC-F5-C4
ACD074	AC-D0-74
9097D5	90-97-D5
600194	60-01-94
240AC4	24-0A-C4
68C63A	68-C6-3A
807D3A	80-7D-3A
246F28	24-6F-28
C4DD57	C4-DD-57
A8032A	A8-03-2A
24A160	24-A1-60
E8DB84	E8-DB-84
E868E7	E8-68-E7
94B97E	94-B9-7E
083AF2	08-3A-F2
E0E2E6	E0-E2-E6
A0764E	A0-76-4E
0CDC7E	0C-DC-7E
3C6105	3C-61-05
8CCE4E	8C-CE-4E`

var EspressifPrefixes [][]byte

func init() {
	scanner := bufio.NewScanner(strings.NewReader(espressifPrefixList))
	for scanner.Scan() {
		line := scanner.Text()
		columns := strings.Split(line, "\t")
		if len(columns) != 2 {
			logrus.WithField("columnCount", len(columns)).WithField("column", line).Fatal("Failed to read columns")
		}
		prefix, err := hex.DecodeString(columns[0])
		if err != nil {
			logrus.WithField("column", columns[0]).WithError(err).Fatal("Failed to parse espressif prefix")
		}
		if len(prefix) > 3 {
			logrus.WithField("column", columns[0]).WithField("prefixLen", len(prefix)).Fatal("Parsed invalid prefix")
		}
		EspressifPrefixes = append(EspressifPrefixes, prefix)
	}
}

var fname = flag.String("f", "", "Filename to read from")

func main() {
	flag.Parse()
	logger := logrus.WithField("filename", *fname)
	h, err := pcap.OpenOffline(*fname)
	if err != nil {
		logger.WithError(err).Fatal("Failed to read input file")
	}
	logger.WithField("espressifPrefixCount", len(EspressifPrefixes)).Info("Checking for espressif prefixes")

	packetSource := gopacket.NewPacketSource(h, h.LinkType())

	foundMacs := make(map[string]gopacket.Packet)

	for packet := range packetSource.Packets() {
		if packet.ErrorLayer() == nil {
			pktInfoLayer := packet.Layer(layers.LayerTypeDot11)

			if pktInfoLayer != nil {
				dot11Info := pktInfoLayer.(*layers.Dot11)
				if checkForEspressif(dot11Info.Address1) {
					logger.WithField("foundMac", dot11Info.Address1).Info("Found espressif device")
					foundMacs[dot11Info.Address1.String()] = packet
				}
				if checkForEspressif(dot11Info.Address2) {
					logger.WithField("foundMac", dot11Info.Address2).Info("Found espressif device")
					foundMacs[dot11Info.Address2.String()] = packet
				}
				if checkForEspressif(dot11Info.Address3) {
					logger.WithField("foundMac", dot11Info.Address3).Info("Found espressif device")
					foundMacs[dot11Info.Address3.String()] = packet
				}
				if checkForEspressif(dot11Info.Address4) {
					logger.WithField("foundMac", dot11Info.Address4).Info("Found espressif device")
					foundMacs[dot11Info.Address4.String()] = packet
				}
			}
		}
	}

	logrus.WithField("deviceCount", len(foundMacs)).Info("Found unique devices")
	for mac, packet := range foundMacs {
		logrus.WithFields(logrus.Fields{
			"mac":    mac,
			"packet": packet.String(),
		}).Info("Found unique device")
	}
}

func checkForEspressif(mac net.HardwareAddr) bool {
	for _, prefix := range EspressifPrefixes {
		if hasMacPrefix(mac, prefix) {
			return true
		}
	}
	return false
}

func hasMacPrefix(mac net.HardwareAddr, prefix []byte) bool {
	if len(prefix) > len(mac) {
		return false
	}
	for i, p := range prefix {
		if mac[i] != p {
			return false
		}
	}
	return true
}

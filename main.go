package main

import (
	"fmt"
	"gtp_parser/gtp"
	"log"
	"sort"
	"sync"
	"time"
	"runtime"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device 			string	= "en0"
	snapshot_len	int32	= 1024
	promiscous		bool	= false
	err				error
	timeout			time.Duration = 30 * time.Second
	handle			*pcap.Handle
)

func findDevice() map[string]string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	interfaces := make(map[string]string)
	fmt.Println("List of available network devices: ")

	for _, device := range devices {
		if len(device.Addresses) <= 0 {
			continue
		}
		var flagIp bool = false;
		for _, address := range device.Addresses {
			if ip4 := address.IP.To4(); ip4 != nil {
				flagIp = true
    			interfaces[device.Name] = ip4.String()
				break
			}
		}
		if flagIp == false {
			continue
		}
	}
	return interfaces
}

func UserInput(s string) int {
	var n int

	fmt.Printf("%s", s)
	fmt.Scan(&n)

	return n
}

func processPacket(packet gopacket.Packet, id int) {
		/* IP Layer */
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			fmt.Printf("[%d] From %s to %s\n",
				id, ip.SrcIP, ip.DstIP)
		}

		/* UDP Layer */
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			fmt.Printf("\t[%d] From port %d to %d\n",
				id, udp.SrcPort, udp.DstPort)
		}

		/* ICM Layer */
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		if icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			fmt.Printf("\t[%d] ICMP type %d code %d\n",
				id, icmp.TypeCode.Type(), icmp.TypeCode.Code())
		}

		/* Print the packet */	
		fmt.Println()
}

func PacketCaptureMode() {
	interfaces := findDevice()
	fmt.Println(interfaces)

	list := make([]string, 0)
	for name, _ := range interfaces {
		list = append(list, name)
	}
	sort.Strings(list)

	for i, v := range list {
		fmt.Printf("[%d] %s - %s\n", i, v, interfaces[v])
	}

	index := UserInput("Input the number of interface you want to capture: ")
	if (len(list) <= index || index < 0) {
		log.Fatal("Available User input : ", err)
	}
	fmt.Println(list[index])

	handle, err := pcap.OpenLive(list[index], snapshot_len, promiscous, timeout)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter("icmp or tcp")
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packetCh := make(chan gopacket.Packet, 100)
	workerCount := runtime.NumCPU()
	fmt.Println("Worker Count: ", workerCount)
	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for packet := range packetCh {
				processPacket(packet, id)
			}
		}(i)
	}

	fmt.Printf("%s 장치에서 패킷 캡처 시작... \n", list[index])
	for packet := range packetSource.Packets() {
		packetCh <- packet
	}
}

func PrintTitle() {
	fmt.Println("== Welcome to GoPacket ==");
	fmt.Println("[1] Packet Capture Mode")
	fmt.Println("[2] Pcap file Read Mode")
}

func PcapFileReadMode() {
	handle, err := pcap.OpenOffline("./sample.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)

			if udp.DstPort == 2123 || udp.SrcPort == 2123 {
				gtp.GtpParse(udp.Payload)
			}
		}
	}
}

func main() {

	PrintTitle()

	mode := UserInput("Input you want mode: ")
	switch mode {
	case 1:
		PacketCaptureMode()
	case 2:
		PcapFileReadMode()
	default:
		log.Fatal("Invalid mode selected")
	}
}
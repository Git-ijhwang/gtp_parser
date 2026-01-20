package main
import (
	"fmt"
	"log"
	"time"
	"sort"

	"github.com/google/gopacket"
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

func UserInput() int {
	var n int

	fmt.Printf("Input the number of interface you want to capture: ")

	fmt.Scan(&n)

	return n
}

func main() {
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

	index := UserInput()
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

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Printf("%s 장치에서 패킷 캡처 시작... \n", list[index])
	for packet := range packetSource.Packets() {
		fmt.Println(packet.String())
	}
}
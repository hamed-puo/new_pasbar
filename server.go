package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

func setupServerTUN(name string) {
	runCmd(fmt.Sprintf("ip addr add %s/24 dev %s", TunIPServer, name))
	runCmd(fmt.Sprintf("ip link set dev %s up", name))
	runCmd("sysctl -w net.ipv4.ip_forward=1")

	out, _ := exec.Command("sh", "-c", "ip route get 8.8.8.8 | grep -oP 'dev \\S+' | head -n1 | awk '{print $2}'").Output()
	wanif := strings.TrimSpace(string(out))
	if wanif == "" {
		wanif = "eth0"
	}

	fmt.Printf("[SERVER] WAN: %s\n", wanif)
	runCmd("iptables -F")
	runCmd("iptables -t nat -F")
	// قانون دقیق نات: جلوگیری از نات شدن ترافیک داخلی تونل
	runCmd(fmt.Sprintf("iptables -t nat -A POSTROUTING -s 10.0.1.0/24 ! -d 10.0.1.0/24 -o %s -j MASQUERADE", wanif))
	runCmd("iptables -A FORWARD -i " + name + " -j ACCEPT")
	runCmd("iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT")
	runCmd("iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
}

func handleClient(conn net.Conn, iface *water.Interface) {
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}

	// خواندن بایت‌به‌بایت هندشیک برای جلوگیری از Buffer Over-read
	marker := []byte("\r\n\r\n")
	match := 0
	b := make([]byte, 1)
	for {
		_, err := conn.Read(b)
		if err != nil {
			return
		}
		if b[0] == marker[match] {
			match++
			if match == len(marker) {
				break
			}
		} else {
			match = 0
			if b[0] == marker[0] {
				match = 1
			}
		}
	}

	conn.Write([]byte(HTTPSuccess))
	fmt.Printf("[+] Client Authenticated: %s\n", conn.RemoteAddr())

	aead, _ := createAead(SharedKey)
	var sendCounter, recvCounter uint64

	go func() {
		packet := make([]byte, 2000)
		for {
			n, err := iface.Read(packet)
			if err != nil {
				break
			}
			if err := EncryptWrite(conn, aead, packet[:n], &sendCounter); err != nil {
				break
			}
		}
	}()

	for {
		decrypted, err := DecryptRead(conn, aead, &recvCounter)
		if err != nil {
			break
		}
		_, _ = iface.Write(decrypted)
	}
}

func main() {
	iface, _ := water.New(water.Config{DeviceType: water.TUN})
	setupServerTUN(iface.Name())
	_, port, _ := net.SplitHostPort(ServerAddr)
	ln, _ := net.Listen("tcp", ":"+port)
	fmt.Printf("[*] Server Listening on :%s\n", port)
	for {
		conn, _ := ln.Accept()
		go handleClient(conn, iface)
	}
}

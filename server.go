package main

import (
	"bufio"
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

	fmt.Printf("[SERVER] WAN: %s | TUN: %s\n", wanif, name)
	runCmd("iptables -F")
	runCmd("iptables -t nat -F")
	// اولویت اول: ترافیک داخلی تونل رو دست نزن (حل مشکل DUP)
	runCmd("iptables -A FORWARD -s 10.0.1.0/24 -d 10.0.1.0/24 -j ACCEPT")
	// فقط ترافیک خروجی به اینترنت را NAT کن
	runCmd(fmt.Sprintf("iptables -t nat -A POSTROUTING -s 10.0.1.0/24 ! -d 10.0.1.0/24 -o %s -j MASQUERADE", wanif))
	runCmd("iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT")
	runCmd("iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
}

func handleClient(conn net.Conn, iface *water.Interface) {
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}

	reader := bufio.NewReader(conn)
	// خواندن هندشیک به صورت بهینه
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	conn.Write([]byte(HTTPSuccess))
	fmt.Printf("[+] Client Authenticated: %s\n", conn.RemoteAddr())

	aead, _ := createAead(SharedKey)
	var sendCounter, recvCounter uint64

	// TUN -> TCP
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

	// TCP -> TUN
	for {
		decrypted, err := DecryptRead(reader, aead, &recvCounter)
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

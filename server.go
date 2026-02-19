package main

import (
	"bufio"
	"fmt"
	"log"
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

	// پاکسازی کامل برای جلوگیری از تداخل
	runCmd("iptables -F")
	runCmd("iptables -t nat -F")
	runCmd("iptables -t mangle -F")

	// قانون طلایی: ترافیک مربوط به خودِ تونل نباید NAT بشه (علت پکت‌های DUP)
	runCmd("iptables -t nat -I POSTROUTING -s 10.0.1.0/24 ! -d 10.0.1.0/24 -o " + wanif + " -j MASQUERADE")
	runCmd("iptables -I FORWARD -i " + name + " -j ACCEPT")
	runCmd("iptables -I FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT")

	// اصلاح MSS برای جلوگیری از فریز شدن TCP
	runCmd("iptables -t mangle -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
}

func handleClient(conn net.Conn, iface *water.Interface) {
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}

	// خواندن هندشیک به صورت خط‌به‌خط (ایمن‌تر)
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	conn.Write([]byte(HTTPSuccess))
	fmt.Printf("[+] Client Online: %s\n", conn.RemoteAddr())

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
			// ارسال فقط اگر مقصد کلاینت باشد (ساده‌سازی)
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
	fmt.Printf("[-] Client Offline: %s\n", conn.RemoteAddr())
}

func main() {
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatal(err)
	}

	setupServerTUN(iface.Name())

	_, port, _ := net.SplitHostPort(ServerAddr)
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("[*] Server Listening on :%s\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn, iface)
	}
}

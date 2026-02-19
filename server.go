package main

import (
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

	// تشخیص اینترفیس اصلی برای NAT
	out, _ := exec.Command("sh", "-c", "ip route get 8.8.8.8 | grep -oP 'dev \\S+' | head -n1 | awk '{print $2}'").Output()
	wanif := strings.TrimSpace(string(out))
	if wanif == "" {
		wanif = "eth0"
	}

	fmt.Printf("[SERVER] WAN Interface: %s\n", wanif)
	runCmd("iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o " + wanif + " -j MASQUERADE")
	runCmd("iptables -A FORWARD -i " + name + " -j ACCEPT")
	runCmd("iptables -A FORWARD -o " + name + " -m state --state ESTABLISHED,RELATED -j ACCEPT")
}

func handleClient(conn net.Conn, iface *water.Interface) {
	defer conn.Close()

	// 1. دریافت Handshake
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "GET /") {
		return
	}

	// 2. تایید Handshake
	_, _ = conn.Write([]byte(HTTPSuccess))
	fmt.Printf("[+] Connection Upgraded for: %s\n", conn.RemoteAddr())

	// 3. ایجاد لایه رمزنگاری
	aead, _ := createAead(SharedKey)
	nonce := make([]byte, aead.NonceSize()) // در حالت ساده، در پروژه‌های واقعی باید داینامیک باشد

	// 4. تونل دیتا: TUN -> TCP (Encrypted)
	go func() {
		packet := make([]byte, 2000)
		for {
			pn, err := iface.Read(packet)
			if err != nil {
				break
			}
			encrypted := aead.Seal(nil, nonce, packet[:pn], nil)
			_, err = conn.Write(encrypted)
			if err != nil {
				break
			}
		}
	}()

	// 5. تونل دیتا: TCP (Encrypted) -> TUN
	for {
		data := make([]byte, 2048)
		dn, err := conn.Read(data)
		if err != nil {
			break
		}
		decrypted, err := aead.Open(nil, nonce, data[:dn], nil)
		if err == nil {
			_, _ = iface.Write(decrypted)
		}
	}
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
	fmt.Printf("[*] VPN Server listening on :%s\n", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn, iface)
	}
}

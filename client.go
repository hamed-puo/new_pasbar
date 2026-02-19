package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/songgao/water"
)

func setupClientTUN(name string) {
	runCmd(fmt.Sprintf("ip addr add %s/24 dev %s", TunIPClient, name))
	runCmd(fmt.Sprintf("ip link set dev %s up", name))
	runCmd(fmt.Sprintf("ip link set dev %s mtu 1200", name)) // MTU کمتر برای پایداری

	out, _ := exec.Command("sh", "-c", "ip route show default | awk '{print $3}' | head -n 1").Output()
	gw := strings.TrimSpace(string(out))

	host, _, _ := net.SplitHostPort(ServerAddr)
	runCmd(fmt.Sprintf("ip route add %s via %s", host, gw))
	runCmd(fmt.Sprintf("ip route add 0.0.0.0/1 dev %s", name))
	runCmd(fmt.Sprintf("ip route add 128.0.0.0/1 dev %s", name))

	// پاکسازی منگل قبلی و ست کردن جدید
	runCmd("iptables -t mangle -F")
	runCmd("iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1100")

	runCmd("cp /etc/resolv.conf /etc/resolv.conf.vpn_bak")
	runCmd("echo 'nameserver 8.8.8.8' > /etc/resolv.conf")
}

func cleanup() {
	fmt.Println("\n[*] Cleaning up...")
	runCmd("ip route del 0.0.0.0/1")
	runCmd("ip route del 128.0.0.0/1")
	host, _, _ := net.SplitHostPort(ServerAddr)
	runCmd(fmt.Sprintf("ip route del %s", host))
	runCmd("iptables -t mangle -F")
	if _, err := os.Stat("/etc/resolv.conf.vpn_bak"); err == nil {
		runCmd("mv /etc/resolv.conf.vpn_bak /etc/resolv.conf")
	}
}

func main() {
	iface, _ := water.New(water.Config{DeviceType: water.TUN})
	setupClientTUN(iface.Name())

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() { <-c; cleanup(); os.Exit(0) }()

	conn, err := net.Dial("tcp", ServerAddr)
	if err != nil {
		cleanup()
		log.Fatal(err)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}

	// ارسال هندشیک
	fmt.Fprintf(conn, HTTPHandshake)

	// خواندن پاسخ هندشیک
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	fmt.Println("[+] Tunnel Established - Ready for test")
	aead, _ := createAead(SharedKey)
	var sendCounter, recvCounter uint64

	// TUN -> TCP
	go func() {
		packet := make([]byte, 2000)
		for {
			pn, err := iface.Read(packet)
			if err != nil {
				break
			}
			if err := EncryptWrite(conn, aead, packet[:pn], &sendCounter); err != nil {
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

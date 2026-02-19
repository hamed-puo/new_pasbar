package main

import (
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
	runCmd(fmt.Sprintf("ip link set dev %s mtu 1300", name))

	// ذخیره گیت‌وی اصلی
	out, _ := exec.Command("sh", "-c", "ip route show default | awk '{print $3}' | head -n 1").Output()
	gw := strings.TrimSpace(string(out))

	host, _, _ := net.SplitHostPort(ServerAddr)

	// روت کردن ایپی سرور از گیت‌وی اصلی جهت جلوگیری از ایجاد لوپ
	runCmd(fmt.Sprintf("ip route add %s via %s", host, gw))

	// روت کردن کل ترافیک از داخل تونل
	runCmd(fmt.Sprintf("ip route add 0.0.0.0/1 dev %s", name))
	runCmd(fmt.Sprintf("ip route add 128.0.0.0/1 dev %s", name))

	// MSS Clamping - بسیار مهم برای جلوگیری از فریز شدن سایت‌ها
	runCmd("iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200")

	// مدیریت DNS
	runCmd("cp /etc/resolv.conf /etc/resolv.conf.vpn_bak")
	runCmd("echo 'nameserver 8.8.8.8' > /etc/resolv.conf")
	runCmd("echo 'nameserver 1.1.1.1' >> /etc/resolv.conf")
}

func cleanup(tunName string) {
	fmt.Println("\n[*] Cleaning up routes and DNS...")
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
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatal(err)
	}

	setupClientTUN(iface.Name())

	// مدیریت سیگنال برای تمیزکاری
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cleanup(iface.Name())
		os.Exit(0)
	}()

	conn, err := net.Dial("tcp", ServerAddr)
	if err != nil {
		cleanup(iface.Name())
		log.Fatal(err)
	}
	defer conn.Close()

	// 1. ارسال Handshake مشابه مرورگر
	_, _ = conn.Write([]byte(HTTPHandshake))

	// 2. تایید موفقیت سوئیچ پروتکل
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil || !strings.Contains(string(resp[:n]), "101 Switching") {
		cleanup(iface.Name())
		log.Fatal("Handshake failed")
	}
	fmt.Println("[+] Tunnel Established via HTTP Fake-Path")

	// 3. لایه رمزنگاری
	aead, _ := createAead(SharedKey)
	nonce := make([]byte, aead.NonceSize())

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

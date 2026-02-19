package main

import (
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"os/exec"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ServerAddr    = "84.247.20.152:8443" // پورت جایگزین (HTTPS Common Alt)
	SharedKey     = "Your-Secret-Shared-Key-Here"
	TunIPClient   = "10.0.1.2"
	TunIPServer   = "10.0.1.1"
	TunNetmask    = "255.255.255.0"
	HTTPHandshake = "GET /favicon.ico HTTP/1.1\r\nHost: encrypted-service.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\nAccept: */*\r\nConnection: upgrade\r\nUpgrade: RawProtocol\r\n\r\n"
	HTTPSuccess   = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: RawProtocol\r\nConnection: Upgrade\r\n\r\n"
)

func createAead(key string) (cipher.AEAD, error) {
	hash := sha256.Sum256([]byte(key))
	return chacha20poly1305.New(hash[:])
}

func runCmd(c string) {
	fmt.Printf("[EXEC] %s\n", c)
	_ = exec.Command("sh", "-c", c).Run()
}

func init() {
	fmt.Println("[*] Configuration Loaded")
}

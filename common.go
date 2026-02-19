package main

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os/exec"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ServerAddr    = "84.247.20.152:8443"
	SharedKey     = "Your-Secret-Shared-Key-Here"
	TunIPClient   = "10.0.1.2"
	TunIPServer   = "10.0.1.1"
	HTTPHandshake = "GET /favicon.ico HTTP/1.1\r\nHost: encrypted-service.com\r\nConnection: upgrade\r\nUpgrade: RawProtocol\r\n\r\n"
	HTTPSuccess   = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: RawProtocol\r\nConnection: Upgrade\r\n\r\n"
)

func createAead(key string) (cipher.AEAD, error) {
	hash := sha256.Sum256([]byte(key))
	return chacha20poly1305.New(hash[:])
}

func getNonce(counter *uint64, size int) []byte {
	nonce := make([]byte, size)
	val := atomic.AddUint64(counter, 1)
	binary.BigEndian.PutUint64(nonce[size-8:], val)
	return nonce
}

func EncryptWrite(w io.Writer, aead cipher.AEAD, packet []byte, counter *uint64) error {
	nonce := getNonce(counter, aead.NonceSize())
	encrypted := aead.Seal(nil, nonce, packet, nil)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(encrypted)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err := w.Write(encrypted)
	return err
}

func DecryptRead(r io.Reader, aead cipher.AEAD, counter *uint64) ([]byte, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf)
	dataBuf := make([]byte, length)
	if _, err := io.ReadFull(r, dataBuf); err != nil {
		return nil, err
	}
	nonce := getNonce(counter, aead.NonceSize())
	return aead.Open(nil, nonce, dataBuf, nil)
}

func runCmd(c string) { _ = exec.Command("sh", "-c", c).Run() }

func init() { fmt.Println("[*] Configuration Loaded") }

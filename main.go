package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"time"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	listenIP    = "0.0.0.0"
	broadcastIP = "255.255.255.255"
	port        = 9002
)

type Payload struct {
	ID        string `json:"id"`
	Service   string `json:"service"`
	PublicKey string `json:"public_key"`
}

type ClientStruct struct {
	IP            string `json:"ip"`
	ID            string `json:"id"`
	PublicKey     string `json:"public_key"`
	IsPaired      bool   `json:"is_paired"`
	DiscoveredOn  string `json:"discovered_on"`
	LastConnected string `json:"last_connected"`
}

var payload Payload

var DataPath string

func main() {
	fmt.Printf("Version: %s\tCommit: %s\tDate: %s\n", version, commit, date)
	DataPath = os.Args[1]

	id, err := os.ReadFile(path.Clean(DataPath + "/id.txt"))
	if err != nil {
		log.Fatal(err)
	}

	if _, err := os.Stat(DataPath + "/private.pem"); errors.Is(err, os.ErrNotExist) {
		GenerateKeyPair()
	}

	publicKey, err := os.ReadFile(DataPath + "/public.pem")
	if err != nil {
		log.Fatal(err)
	}

	payload = Payload{
		ID:        strings.TrimSpace(string(id)),
		Service:   "clearnotes",
		PublicKey: string(publicKey),
	}

	go Server()
	go Client()

	time.Sleep(30 * time.Second)
}

func Server() {
	serverAddr := fmt.Sprintf("%s:%d", broadcastIP, port)

	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		log.Fatalf("[SERVER] Some error %v\n", err)
		return
	}
	defer conn.Close()

	fmt.Printf("[SERVER] Broadcasting over UDP on %s:%d...\n", broadcastIP, port)

	for {
		_, err := conn.Write(EncodeToBytes(&payload))
		if err != nil {
			fmt.Printf("[SERVER] Some error %v\n", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func Client() {
	addr := fmt.Sprintf("%s:%d", listenIP, port)

	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatal("[CLIENT] Error listening on UDP port:", err)
		return
	}
	defer conn.Close()

	fmt.Printf("[CLIENT] Listening for UDP broadcasts on %s:%d...\n", listenIP, port)

	buf := make([]byte, 1024)

	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Println("[CLIENT] Error reading from UDP connection:", err)
			return
		}

		resPayload := DecodeToPayload(buf[:n])
		ip := strings.Split(addr.String(), ":")[0]

		content, err := os.ReadFile(DataPath + "/clients.txt")
		if err != nil {
			fmt.Println("[CLIENT] Error reading from clients.txt:", err)
			return
		}

		var clients []ClientStruct

		err = json.Unmarshal(content, &clients)
		if err != nil {
			log.Fatal("[CLIENT] Error parsing clients.txt:", err)
		}

		for _, client := range clients {
			if client.IP != ip && resPayload.ID != payload.ID {
				clients = append(clients, ClientStruct{
					IP:            strings.TrimSpace(ip),
					ID:            strings.TrimSpace(resPayload.ID),
					PublicKey:     resPayload.PublicKey,
					DiscoveredOn:  time.Now().UTC().Format(time.RFC3339),
					LastConnected: time.Now().UTC().Format(time.RFC3339),
				})
			}
		}

		if len(clients) == 0 && resPayload.ID != payload.ID {
			clients = append(clients, ClientStruct{
				IP:            strings.TrimSpace(ip),
				ID:            strings.TrimSpace(resPayload.ID),
				PublicKey:     resPayload.PublicKey,
				DiscoveredOn:  time.Now().UTC().Format(time.RFC3339),
				LastConnected: time.Now().UTC().Format(time.RFC3339),
			})
		}

		b, err := json.Marshal(clients)
		if err != nil {
			log.Fatal("[CLIENT] Error marshalling clients:", err)
		}

		err = os.WriteFile(DataPath+"/clients.txt", b, 0664)
		if err != nil {
			log.Fatal("[CLIENT] Error writing clients.txt:", err)
		}

		fmt.Printf("[CLIENT] Received message from %s (%s): %s\n", addr.String(), strings.Trim(resPayload.ID, "\n"), resPayload.Service)
	}
}

func EncodeToBytes(p interface{}) []byte {
	buf := bytes.Buffer{}
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(p)
	if err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
}

func DecodeToPayload(s []byte) Payload {
	p := Payload{}
	dec := gob.NewDecoder(bytes.NewReader(s))
	err := dec.Decode(&p)
	if err != nil {
		log.Fatal(err)
	}
	return p
}

func GenerateKeyPair() {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	publickey := &privatekey.PublicKey

	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create(DataPath + "/private.pem")
	if err != nil {
		fmt.Printf("error when create private.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		fmt.Printf("error when encode private pem: %s \n", err)
		os.Exit(1)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		fmt.Printf("error when dumping publickey: %s \n", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	publicPem, err := os.Create(DataPath + "/public.pem")
	if err != nil {
		fmt.Printf("error when create public.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		fmt.Printf("error when encode public pem: %s \n", err)
		os.Exit(1)
	}
}

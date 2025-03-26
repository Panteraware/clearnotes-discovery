package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"slices"
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
	ID      string `json:"id"`
	Service string `json:"service"`
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

	payload = Payload{
		ID:      string(id),
		Service: "clearnotes",
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

		payload := DecodeToPayload(buf[:n])

		content, err := os.ReadFile(DataPath + "/clients.txt")
		if err != nil {
			fmt.Println("[CLIENT] Error reading from clients.txt:", err)
			return
		}

		clients := strings.Split(string(content), "\n")

		if !slices.Contains(clients, strings.Split(addr.String(), ":")[0]) {
			clients = append(clients, strings.Split(addr.String(), ":")[0])
		}

		err = os.WriteFile(DataPath+"/clients.txt", []byte(strings.Join(clients, "\n")), 0664)

		fmt.Printf("[CLIENT] Received message from %s (%s): %s\n", addr.String(), strings.Trim(payload.ID, "\n"), payload.Service)
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

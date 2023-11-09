package main

import (
	"fmt"
	"net"
)

func main() {
	fmt.Println("Server is running at localhost:8888")
	conn, err := net.ListenPacket("udp4", "localhost:8888")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	buff := make([]byte, 1500)
	for {
		len, remoteAddress, err := conn.ReadFrom(buff)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Received from %v: %v\n", remoteAddress, string(buff[:len]))
		_, err = conn.WriteTo([]byte("Hello from Server"), remoteAddress)
		if err != nil {
			panic(err)
		}
	}

}

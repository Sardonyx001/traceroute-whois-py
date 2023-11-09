package main

import (
	"fmt"
	"net"
)

func main() {
	fmt.Println("Server is running at localhost")
	conn, err := net.ListenPacket("ip4:icmp", "")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	buff := make([]byte, 512)
	for {
		len, remoteAddress, err := conn.ReadFrom(buff)
		if len < 0 || err != nil {
			panic(err)
		}
		fmt.Printf("Received from %v: %v\n", remoteAddress, string(buff[:len]))
		_, err = conn.WriteTo([]byte("Hello from Server"), remoteAddress)
		if err != nil {
			panic(err)
		}
	}

}

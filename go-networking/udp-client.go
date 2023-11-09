package main

import (
	"fmt"
	"net"
)

func main() {
	conn, err := net.Dial("udp4", "localhost:8888")
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	fmt.Println("Sending to server")
	_, err = conn.Write([]byte("Hello from Client"))
	if err != nil {
		panic(err)
	}
	fmt.Println("Receiving from server")
	buff := make([]byte, 1500)
	len, err := conn.Read(buff)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Received: %s\n", string(buff[:len]))

}

package main

import (
	"fmt"
	"github.com/gorilla/websocket"
)

// Types

// Endpoint: address:port
type Endpoint struct {
	Host string
	Port string
}

func (endpoint *Endpoint) String() string {
	return fmt.Sprintf("%s:%s", endpoint.Host, endpoint.Port)
}

// Websocket connection
type wsConn struct {
	*websocket.Conn
	buff []byte
}

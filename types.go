package main

import (
	"fmt"
	"github.com/gorilla/websocket"
)

// Types
type Endpoint struct {
	Host string
	Port string
}

func (endpoint *Endpoint) String() string {
	return fmt.Sprintf("%s:%s", endpoint.Host, endpoint.Port)
}

type wsConn struct {
	*websocket.Conn
	buff []byte
}
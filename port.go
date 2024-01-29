package netx

import (
	"fmt"
	"net"
	"time"
)

// IsTCPPortInUse tests to see if the given host address and port are available and accepting connections.
func IsTCPPortInUse(hostIP, port string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", hostIP, port), 2*time.Second)
	if err != nil || conn == nil {
		return false
	}
	conn.Close()
	return true
}

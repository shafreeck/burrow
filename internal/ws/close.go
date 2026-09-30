package ws

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

// CloseInfo retains the wire close status. 1005 means no status was supplied.
func CloseInfo(payload []byte) (int, string) {
	if len(payload) == 0 {
		return 1005, ""
	}
	if len(payload) < 2 || !utf8.Valid(payload[2:]) {
		return 1002, "invalid close payload"
	}
	return int(binary.BigEndian.Uint16(payload)), string(payload[2:])
}

type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	return fmt.Sprintf("remote websocket close code=%d reason=%q", e.Code, e.Reason)
}

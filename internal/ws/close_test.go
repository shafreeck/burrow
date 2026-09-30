package ws

import "testing"

func TestCloseInfo(t *testing.T) {
	for _, v := range []struct {
		p      []byte
		code   int
		reason string
	}{{nil, 1005, ""}, {[]byte{3, 232, 'b', 'y', 'e'}, 1000, "bye"}, {[]byte{3}, 1002, "invalid close payload"}, {[]byte{3, 232, 255}, 1002, "invalid close payload"}} {
		c, r := CloseInfo(v.p)
		if c != v.code || r != v.reason {
			t.Fatalf("%d %q", c, r)
		}
	}
}

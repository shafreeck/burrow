package server

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/shafreeck/burrow/internal/proto"
)

type pendingRequest struct {
	agent *agentConn
	reply chan map[string]interface{}
}

// receive drains bytes received before a remote close. Selecting directly
// between toNet and done can discard the last response when both are ready.
func (st *stream) receive() ([]byte, bool) {
	select {
	case data := <-st.toNet:
		return data, true
	default:
	}
	select {
	case data := <-st.toNet:
		return data, true
	case <-st.done:
		select {
		case data := <-st.toNet:
			return data, true
		default:
			return nil, false
		}
	}
}

func (s *Server) endAgentStream(st *stream) {
	s.closeStream(st.id)
	msg, _ := json.Marshal(map[string]string{"type": proto.TypeClose, "id": st.id})
	st.agent.ws.WriteText(msg)
}

// Register before sending connect: a server-first protocol can send data and
// EOF immediately after connect_result, before the inbound handler resumes.
func (s *Server) openAgentStream(ac *agentConn, host string, port int) (*stream, error) {
	st := &stream{id: newID(), agent: ac, toNet: make(chan []byte, 64), done: make(chan struct{})}
	s.streamsMu.Lock()
	s.streams[st.id] = st
	s.streamsMu.Unlock()
	ch := make(chan map[string]interface{}, 1)
	s.pendingMu.Lock()
	s.pending[st.id] = &pendingRequest{agent: ac, reply: ch}
	s.pendingMu.Unlock()
	succeeded := false
	defer func() {
		s.pendingMu.Lock()
		delete(s.pending, st.id)
		s.pendingMu.Unlock()
		if !succeeded {
			s.endAgentStream(st)
		}
	}()
	req, _ := json.Marshal(map[string]interface{}{"type": proto.TypeConnect, "id": st.id, "host": host, "port": port})
	if err := ac.ws.WriteText(req); err != nil {
		return nil, err
	}
	select {
	case res := <-ch:
		if ok, _ := res["ok"].(bool); !ok {
			return nil, fmt.Errorf("agent connect failed: %v", res["error"])
		}
		succeeded = true
		return st, nil
	case <-time.After(15 * time.Second):
		return nil, fmt.Errorf("agent connect timed out")
	}
}

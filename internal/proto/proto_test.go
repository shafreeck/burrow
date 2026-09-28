package proto

import (
	"bytes"
	"testing"
)

func TestDataFrameRoundtrip(t *testing.T) {
	id := "stream-123"
	payload := []byte("hello world, this is binary data \x00\xff")
	frame := EncodeDataFrame(id, payload)
	gotID, gotPayload, ok := DecodeDataFrame(frame)
	if !ok {
		t.Fatal("decode failed")
	}
	if gotID != id {
		t.Fatalf("id mismatch: %q != %q", gotID, id)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestDataFrameEmpty(t *testing.T) {
	frame := EncodeDataFrame("x", nil)
	id, payload, ok := DecodeDataFrame(frame)
	if !ok || id != "x" || len(payload) != 0 {
		t.Fatalf("empty payload failed: %v %q %v", ok, id, payload)
	}
}

func TestDataFrameCorrupt(t *testing.T) {
	if _, _, ok := DecodeDataFrame(nil); ok {
		t.Fatal("nil should fail")
	}
	if _, _, ok := DecodeDataFrame([]byte{5, 'a', 'b'}); ok {
		t.Fatal("truncated should fail")
	}
}

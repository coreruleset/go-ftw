package http

import (
	"testing"
)

func TestDestination(t *testing.T) {
	d := &Destination{
		DestAddr: "192.168.1.1",
		Port:     443,
		Protocol: "https",
	}

	if d.DestAddr == "192.168.1.1" && d.Port == 443 && d.Protocol == "https" {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
}

func TestRequestNew(t *testing.T) {
	var req *Request

	d := &Destination{
		DestAddr: "192.168.1.1",
		Port:     443,
		Protocol: "https",
	}

	rl := &RequestLine{
		Method:  "UNEXISTENT",
		URI:     "/this/path",
		Version: "1.4",
	}

	h := Header{"This": "Header", "Connection": "Not-Closed"}

	req = req.NewRequest(d, rl, h, []byte("Data"), []byte{}, true)

	head := req.Headers()
	if head.Get("This") == "Header" {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
}

package client

import (
	"encoding/base64"
	"testing"
	"time"
)

func Test_SimpleClient(t *testing.T) {
	c := NewAesGcmClient("http://127.0.0.1:20000/wdals")
	if c.sessionTicketExpire < uint32(time.Now().Unix()) {
		err := c.Handshake()
		if err != nil {
			t.Fatal(err)
		}
		t.Log("client", "ticketExpire", c.sessionTicketExpire, "ticket", base64.StdEncoding.EncodeToString(c.sessionTicket))
	}

	var req = []byte("ping")
	rsp, err := c.Request(req)
	t.Log(string(rsp), err)
}

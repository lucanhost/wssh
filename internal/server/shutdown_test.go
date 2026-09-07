package server

import (
	"testing"
	"time"
)

func TestWaitDrainsActiveSessions(t *testing.T) {
	signer, line := testSigner(t)
	srv, wsURL := newTestServer(t, line, 0)
	cl := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start("sleep 30"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		srv.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Wait returned while session active")
	case <-time.After(500 * time.Millisecond):
	}

	cl.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after connection close")
	}
}

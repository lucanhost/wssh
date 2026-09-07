package server

import (
	"errors"
	"os"
	"os/user"
	"testing"
)

func TestCredentialsForNonRootReturnsNil(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping non-root test while running as root")
	}
	u := &user.User{Uid: "1000", Gid: "1000"}
	cred, err := credentialsFor(u)
	if cred != nil || err != nil {
		t.Fatalf("non-root: cred=%v err=%v, want nil,nil", cred, err)
	}
}

func TestCredentialsForRootMalformedUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping root test while running as non-root")
	}
	cases := []struct {
		name string
		u    *user.User
	}{
		{"uid abc", &user.User{Uid: "abc", Gid: "0"}},
		{"gid abc", &user.User{Uid: "0", Gid: "abc"}},
		{"both empty", &user.User{Uid: "", Gid: ""}},
		{"negative uid", &user.User{Uid: "-1", Gid: "0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := credentialsFor(tc.u)
			if cred != nil {
				t.Fatalf("cred = %v, want nil", cred)
			}
			if err == nil {
				t.Fatal("expected error for malformed uid/gid")
			}
			if !errors.Is(err, ErrMalformedCredential) {
				t.Fatalf("err = %v, want ErrMalformedCredential", err)
			}
		})
	}
}

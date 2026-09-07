package client

func PlaintextNote(t *Target) string {
	if t.Scheme == "ws" {
		return "wssh: note: plaintext ws:// transport; SSH crypto still applies, but prefer wss:// on untrusted networks"
	}
	return ""
}

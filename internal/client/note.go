package client

// PlaintextNote returns a one-line warning about plaintext ws:// targets
// (SSH crypto still applies; wss:// is recommended on untrusted networks)
// and an empty string for wss:// targets.
func PlaintextNote(t *Target) string {
	if t.Scheme == "ws" {
		return "wssh: note: plaintext ws:// transport; SSH crypto still applies, but prefer wss:// on untrusted networks"
	}
	return ""
}

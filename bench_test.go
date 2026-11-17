package argon2_test

import (
	"testing"

	xargon2 "golang.org/x/crypto/argon2"

	"github.com/go-encryptions/argon2"
)

var salt = []byte("theca-bench-salt")

// The Theca unlock profile 1 shape on one lane: t=3, m=64 MiB.
func BenchmarkIDKeyT3M64(b *testing.B) {
	for b.Loop() {
		argon2.IDKey([]byte("password"), salt, 3, 64<<10, 1, 32)
	}
}

func BenchmarkXCryptoIDKeyT3M64(b *testing.B) {
	for b.Loop() {
		xargon2.IDKey([]byte("password"), salt, 3, 64<<10, 1, 32)
	}
}

// The two must agree, whatever their speed.
func TestAgainstXCrypto(t *testing.T) {
	for _, p := range []struct {
		time, mem uint32
		threads   uint8
	}{{1, 64, 1}, {3, 1024, 1}, {2, 2048, 4}, {4, 4096, 3}} {
		if string(argon2.IDKey([]byte("pw"), salt, p.time, p.mem, p.threads, 32)) != string(xargon2.IDKey([]byte("pw"), salt, p.time, p.mem, p.threads, 32)) {
			t.Fatalf("IDKey differs from x/crypto for %+v", p)
		}
		if string(argon2.Key([]byte("pw"), salt, p.time, p.mem, p.threads, 64)) != string(xargon2.Key([]byte("pw"), salt, p.time, p.mem, p.threads, 64)) {
			t.Fatalf("Key differs from x/crypto for %+v", p)
		}
	}
}

//go:build arm64 && gc && !purego

package argon2

import (
	"math/rand/v2"
	"testing"
)

func randBlock(r *rand.Rand) *block {
	var b block
	for i := range b {
		b[i] = r.Uint64()
	}
	return &b
}

// Every kernel is held to processBlockGeneric on random blocks, with out
// distinct from the inputs and with out aliasing in1 (Argon2's address blocks
// do that) or in2.
func TestKernelsAgainstGeneric(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 9))
	kernels := []struct {
		name string
		f    func(out, in1, in2 *block)
		xor  bool
		skip bool
	}{
		{"NEON", processBlockNEON, false, false},
		{"NEON xor", processBlockXORNEON, true, false},
		{"SHA3", processBlockSHA3, false, !useSHA3},
		{"SHA3 xor", processBlockXORSHA3, true, !useSHA3},
	}
	for _, k := range kernels {
		if k.skip {
			t.Logf("%s: no SHA-3 extension on this CPU", k.name)
			continue
		}
		for range 2000 {
			in1, in2, out0 := randBlock(r), randBlock(r), randBlock(r)
			want, got := *out0, *out0
			processBlockGeneric(&want, in1, in2, k.xor)
			k.f(&got, in1, in2)
			if got != want {
				t.Fatalf("%s: differs from the generic code", k.name)
			}
			// out aliases in1.
			a, wa := *in1, *in1
			processBlockGeneric(&wa, &wa, in2, k.xor)
			k.f(&a, &a, in2)
			if a != wa {
				t.Fatalf("%s: differs with out == in1", k.name)
			}
			// out aliases in2.
			b, wb := *in2, *in2
			processBlockGeneric(&wb, in1, &wb, k.xor)
			k.f(&b, in1, &b)
			if b != wb {
				t.Fatalf("%s: differs with out == in2", k.name)
			}
		}
	}
}

// The public functions take the SHA-3 kernels when the CPU has them, so the
// plain NEON ones are run end to end here by turning the switch off.
func TestIDKeyNEON(t *testing.T) {
	salt := []byte("0123456789abcdef")
	orig := useSHA3
	defer func() { useSHA3 = orig }()
	for _, p := range []struct {
		time, mem uint32
		threads   uint8
	}{{1, 64, 1}, {3, 256, 1}, {2, 512, 4}, {1, 1024, 2}} {
		useSHA3 = false
		neon := IDKey([]byte("pw"), salt, p.time, p.mem, p.threads, 32)
		kneon := Key([]byte("pw"), salt, p.time, p.mem, p.threads, 32)
		useSHA3 = orig
		sha3 := IDKey([]byte("pw"), salt, p.time, p.mem, p.threads, 32)
		ksha3 := Key([]byte("pw"), salt, p.time, p.mem, p.threads, 32)
		if string(neon) != string(sha3) || string(kneon) != string(ksha3) {
			t.Fatalf("%+v: the two kernels disagree", p)
		}
	}
}

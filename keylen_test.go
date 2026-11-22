package argon2

import (
	"strings"
	"testing"
)

// keyLen == 0 used to crash with a nil-pointer dereference (blake2b.New(0)
// returns a nil hash and an error that was ignored). It is refused with a clear
// message, as time < 1 and threads < 1 are.
func TestKeyLenZeroPanicsClearly(t *testing.T) {
	for name, f := range map[string]func(){
		"IDKey": func() { IDKey([]byte("pw"), []byte("saltsalt"), 1, 64, 1, 0) },
		"Key":   func() { Key([]byte("pw"), []byte("saltsalt"), 1, 64, 1, 0) },
	} {
		func() {
			defer func() {
				r := recover()
				s, ok := r.(string)
				if !ok || !strings.Contains(s, "key length too small") {
					t.Errorf("%s(keyLen=0): panic = %v, want the clear \"key length too small\" message", name, r)
				}
			}()
			f()
		}()
	}
	// The smallest valid length still works.
	if k := IDKey([]byte("pw"), []byte("saltsalt"), 1, 64, 1, 1); len(k) != 1 {
		t.Errorf("keyLen=1 returned %d bytes", len(k))
	}
}

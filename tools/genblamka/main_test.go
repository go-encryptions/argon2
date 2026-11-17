package main

import (
	"os"
	"strings"
	"testing"
)

// The committed kernel is the generator's output, byte for byte.
func TestCommittedAssemblyIsGenerated(t *testing.T) {
	want, err := os.ReadFile("../../blamka_arm64.s")
	if err != nil {
		t.Fatal(err)
	}
	if got := generate(); got != string(want) {
		t.Fatal("blamka_arm64.s is stale: go run ./tools/genblamka > blamka_arm64.s")
	}
}

func TestEveryKernelIsEmitted(t *testing.T) {
	g := generate()
	for _, name := range []string{"processBlockNEON", "processBlockXORNEON", "processBlockSHA3", "processBlockXORSHA3"} {
		if !strings.Contains(g, "TEXT ·"+name+"(SB)") {
			t.Errorf("%s is missing", name)
		}
	}
	// Only the SHA-3 forms may use XAR.
	if strings.Count(g, "VXAR") == 0 {
		t.Error("no XAR in the SHA-3 kernels")
	}
}

// Command genblamka writes blamka_arm64.s, the NEON implementation of the
// Argon2 compression function G (RFC 9106 section 3.5), to standard output.
//
//	go run ./tools/genblamka > blamka_arm64.s
//
// The assembly is generated because the kernel interleaves the instruction
// streams of independent BLAKE2b rounds by hand, which does not survive
// manual editing. generate_test.go holds the committed file to this output.
//
// Layout. One 1 KiB block is 128 uint64. G applies the BLAMKA permutation to
// the eight rows of 16 words, then to the eight "columns" of 16 words (two
// adjacent words at a stride of 16, see processBlockGeneric). In both passes
// the 16 words are eight 2-lane vectors in the same register roles:
//
//	R0=(v0,v1) R1=(v2,v3) R2=(v4,v5) R3=(v6,v7)
//	R4=(v8,v9) R5=(v10,v11) R6=(v12,v13) R7=(v14,v15)
//
// so the first (column) step of the round is two 2-lane BLAKE2b G on
// (R0,R2,R4,R6) and (R1,R3,R5,R7), and the diagonal step is the same on
// (R0,B0,R5,D0) and (R1,B1,R4,D1) with B0=(v5,v6) B1=(v7,v4) D0=(v15,v12)
// D1=(v13,v14), built with EXT and undone after. Two rows are processed at
// once (V0-V7 and V12-V19) so the four dependent chains overlap.
//
// The multiply 2*lo32(a)*lo32(b) is XTN+UMLAL twice. The XAR variant (Armv8.2
// SHA-3, which every Apple core has) folds each XOR-and-rotate into one
// instruction.
package main

import (
	"fmt"
	"os"
	"strings"
)

// A set is the registers of one row in flight.
type set struct {
	r [8]int // the row, as above
	t [4]int // temporaries
}

var sets = [2]set{
	{r: [8]int{0, 1, 2, 3, 4, 5, 6, 7}, t: [4]int{8, 9, 10, 11}},
	{r: [8]int{12, 13, 14, 15, 16, 17, 18, 19}, t: [4]int{20, 21, 22, 23}},
}

const (
	r24 = 24 // TBL index: rotate each 64-bit lane right by 24
	r16 = 25 // and by 16
)

func v(n int) string { return fmt.Sprintf("V%d", n) }

// stream is one set's instructions for one phase.
type stream []string

func (s *stream) add(f string, a ...any) { *s = append(*s, "\t"+fmt.Sprintf(f, a...)) }

// interleave emits the streams round-robin, which spreads independent chains
// over the core's issue window.
func interleave(w *strings.Builder, ss ...stream) {
	for i := 0; ; i++ {
		any := false
		for _, s := range ss {
			if i < len(s) {
				w.WriteString(s[i])
				w.WriteByte('\n')
				any = true
			}
		}
		if !any {
			return
		}
	}
}

// addmul: a = a + b + 2*lo32(a)*lo32(b), with t0 t1 scratch.
func (s *stream) addmul(a, b, t0, t1 int) {
	s.add("VXTN %s.D2, %s.S2", v(a), v(t0))
	s.add("VXTN %s.D2, %s.S2", v(b), v(t1))
	s.add("VADD %s.D2, %s.D2, %s.D2", v(b), v(a), v(a))
	s.add("VUMLAL %s.S2, %s.S2, %s.D2", v(t1), v(t0), v(a))
	s.add("VUMLAL %s.S2, %s.S2, %s.D2", v(t1), v(t0), v(a))
}

// xorrot: x = ror(x ^ y, n) for n in {32, 24, 16, 63}.
func (s *stream) xorrot(x, y, n, t int, xar bool) {
	if xar {
		s.add("VXAR $%d, %s.D2, %s.D2, %s.D2", n, v(y), v(x), v(x))
		return
	}
	s.add("VEOR %s.B16, %s.B16, %s.B16", v(y), v(x), v(x))
	switch n {
	case 32:
		s.add("VREV64 %s.S4, %s.S4", v(x), v(x))
	case 24:
		s.add("VTBL %s.B16, [%s.B16], %s.B16", v(r24), v(x), v(x))
	case 16:
		s.add("VTBL %s.B16, [%s.B16], %s.B16", v(r16), v(x), v(x))
	case 63:
		s.add("VSHL $1, %s.D2, %s.D2", v(x), v(t))
		s.add("VUSRA $63, %s.D2, %s.D2", v(x), v(t))
		s.add("VORR %s.B16, %s.B16, %s.B16", v(t), v(t), v(x))
	}
}

// g is the 2-lane BLAKE2b G of Argon2 (with the multiplication) on a b c d.
func (s *stream) g(a, b, c, d, t0, t1 int, xar bool) {
	s.addmul(a, b, t0, t1)
	s.xorrot(d, a, 32, t0, xar)
	s.addmul(c, d, t0, t1)
	s.xorrot(b, c, 24, t0, xar)
	s.addmul(a, b, t0, t1)
	s.xorrot(d, a, 16, t0, xar)
	s.addmul(c, d, t0, t1)
	s.xorrot(b, c, 63, t0, xar)
}

// round emits BLAMKA on the row held in x's registers.
func round(w *strings.Builder, xar bool) {
	var col, diag [4]stream
	var shuf, unsh [2]stream
	for i, x := range sets {
		r, t := x.r, x.t
		// Column step: pairs (R0,R2,R4,R6) and (R1,R3,R5,R7).
		col[2*i].g(r[0], r[2], r[4], r[6], t[0], t[1], xar)
		col[2*i+1].g(r[1], r[3], r[5], r[7], t[2], t[3], xar)
		// Rotate B and D into diagonals: they land in the temporaries,
		// which frees R2 R3 R6 R7 as scratch for the diagonal step.
		shuf[i].add("VEXT $8, %s.B16, %s.B16, %s.B16", v(r[3]), v(r[2]), v(t[0])) // B0 = (v5,v6)
		shuf[i].add("VEXT $8, %s.B16, %s.B16, %s.B16", v(r[2]), v(r[3]), v(t[1])) // B1 = (v7,v4)
		shuf[i].add("VEXT $8, %s.B16, %s.B16, %s.B16", v(r[6]), v(r[7]), v(t[2])) // D0 = (v15,v12)
		shuf[i].add("VEXT $8, %s.B16, %s.B16, %s.B16", v(r[7]), v(r[6]), v(t[3])) // D1 = (v13,v14)
		diag[2*i].g(r[0], t[0], r[5], t[2], r[2], r[3], xar)
		diag[2*i+1].g(r[1], t[1], r[4], t[3], r[6], r[7], xar)
		unsh[i].add("VEXT $8, %s.B16, %s.B16, %s.B16", v(t[0]), v(t[1]), v(r[2]))
		unsh[i].add("VEXT $8, %s.B16, %s.B16, %s.B16", v(t[1]), v(t[0]), v(r[3]))
		unsh[i].add("VEXT $8, %s.B16, %s.B16, %s.B16", v(t[3]), v(t[2]), v(r[6]))
		unsh[i].add("VEXT $8, %s.B16, %s.B16, %s.B16", v(t[2]), v(t[3]), v(r[7]))
	}
	interleave(w, col[:]...)
	interleave(w, shuf[0], shuf[1])
	interleave(w, diag[:]...)
	interleave(w, unsh[0], unsh[1])
}

// load8 loads 8 vectors, each from base+off(j) with FMOVQ.
func fq(op, reg, base string, off int) string {
	if op == "ld" {
		return fmt.Sprintf("\tFMOVQ %d(%s), F%s", off, base, reg)
	}
	return fmt.Sprintf("\tFMOVQ F%s, %d(%s)", reg, off, base)
}

// function emits one TEXT. xor selects out ^= ..., xar the SHA-3 rounds.
func function(w *strings.Builder, name string, xor, xar bool) {
	fmt.Fprintf(w, "// func %s(out, in1, in2 *block)\n", name)
	fmt.Fprintf(w, "TEXT ·%s(SB), $1056-24\n", name)
	w.WriteString(`	MOVD	out+0(FP), R0
	MOVD	in1+8(FP), R1
	MOVD	in2+16(FP), R2
	ADD	$16, RSP, R3		// t: 1 KiB of the frame
	MOVD	$consts<>(SB), R9
	FMOVQ	(R9), F24
	FMOVQ	16(R9), F25

	// Pass 1: t = in1 ^ in2, BLAMKA on each row of 16 words, two rows at a time.
	MOVD	R3, R4			// t cursor
	MOVD	R1, R5
	MOVD	R2, R6
	MOVD	$4, R7
pass1:
`)
	for i, x := range sets {
		for j := 0; j < 8; j++ {
			w.WriteString(fq("ld", fmt.Sprint(x.r[j]), "R5", i*128+16*j) + "\n")
			w.WriteString(fq("ld", fmt.Sprint(x.t[j%4]), "R6", i*128+16*j) + "\n")
			fmt.Fprintf(w, "\tVEOR %s.B16, %s.B16, %s.B16\n", v(x.t[j%4]), v(x.r[j]), v(x.r[j]))
		}
	}
	round(w, xar)
	for i, x := range sets {
		for j := 0; j < 8; j++ {
			w.WriteString(fq("st", fmt.Sprint(x.r[j]), "R4", i*128+16*j) + "\n")
		}
	}
	w.WriteString(`	ADD	$256, R4
	ADD	$256, R5
	ADD	$256, R6
	SUBS	$1, R7
	BNE	pass1

	// Pass 2: the columns, two at a time (16 bytes apart), then
	// out = [out ^] in1 ^ in2 ^ t.
	MOVD	$4, R7
pass2:
`)
	// Column k (16*k bytes in): vector j at j*128. Two columns: k and k+1.
	for i, x := range sets {
		for j := 0; j < 8; j++ {
			w.WriteString(fq("ld", fmt.Sprint(x.r[j]), "R3", j*128+16*i) + "\n")
		}
	}
	round(w, xar)
	for i, x := range sets {
		for j := 0; j < 8; j++ {
			off := j*128 + 16*i
			w.WriteString(fq("ld", fmt.Sprint(x.t[0]), "R1", off) + "\n")
			w.WriteString(fq("ld", fmt.Sprint(x.t[1]), "R2", off) + "\n")
			fmt.Fprintf(w, "\tVEOR %s.B16, %s.B16, %s.B16\n", v(x.t[1]), v(x.t[0]), v(x.t[0]))
			fmt.Fprintf(w, "\tVEOR %s.B16, %s.B16, %s.B16\n", v(x.t[0]), v(x.r[j]), v(x.r[j]))
			if xor {
				w.WriteString(fq("ld", fmt.Sprint(x.t[0]), "R0", off) + "\n")
				fmt.Fprintf(w, "\tVEOR %s.B16, %s.B16, %s.B16\n", v(x.t[0]), v(x.r[j]), v(x.r[j]))
			}
			w.WriteString(fq("st", fmt.Sprint(x.r[j]), "R0", off) + "\n")
		}
	}
	w.WriteString(`	ADD	$32, R3
	ADD	$32, R0
	ADD	$32, R1
	ADD	$32, R2
	SUBS	$1, R7
	BNE	pass2
	RET

`)
}

func generate() string {
	var w strings.Builder
	w.WriteString(`// Code generated by tools/genblamka; DO NOT EDIT.

//go:build arm64 && gc && !purego

#include "textflag.h"

// TBL indexes: rotate every 64-bit lane right by 24 and by 16 bits.
DATA consts<>+0(SB)/8, $0x0201000706050403
DATA consts<>+8(SB)/8, $0x0a09080f0e0d0c0b
DATA consts<>+16(SB)/8, $0x0100070605040302
DATA consts<>+24(SB)/8, $0x09080f0e0d0c0b0a
GLOBL consts<>(SB), RODATA|NOPTR, $32

`)
	function(&w, "processBlockNEON", false, false)
	function(&w, "processBlockXORNEON", true, false)
	function(&w, "processBlockSHA3", false, true)
	function(&w, "processBlockXORSHA3", true, true)
	return w.String()
}

func main() {
	if _, err := fmt.Fprint(os.Stdout, generate()); err != nil {
		os.Exit(1)
	}
}

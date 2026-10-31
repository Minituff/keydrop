// Package qr encodes text as a QR code: byte mode, error correction level M,
// versions 1–15 (up to 412 bytes). That's plenty for an otpauth:// link, and
// keeps keydrop free of third-party dependencies.
package qr

import (
	"errors"
	"fmt"
	"strings"
)

// Code is a square grid of modules; true is dark.
type Code struct {
	Size int
	mod  []bool
}

// Dark reports whether the module at column x, row y is dark.
func (c *Code) Dark(x, y int) bool { return c.mod[y*c.Size+x] }

// ErrTooLong is returned for text that doesn't fit in version 15.
var ErrTooLong = errors.New("qr: text too long")

// Error correction blocks for level M, by version: EC codewords per block,
// then (count, data codewords) for the two block groups.
var blocksM = [16][5]int{
	{},
	{10, 1, 16, 0, 0}, {16, 1, 28, 0, 0}, {26, 1, 44, 0, 0}, {18, 2, 32, 0, 0},
	{24, 2, 43, 0, 0}, {16, 4, 27, 0, 0}, {18, 4, 31, 0, 0}, {22, 2, 38, 2, 39},
	{22, 3, 36, 2, 37}, {26, 4, 43, 1, 44}, {30, 1, 50, 4, 51}, {22, 6, 36, 2, 37},
	{22, 8, 37, 1, 38}, {24, 4, 40, 5, 41}, {24, 5, 41, 5, 42},
}

// Alignment pattern centres, by version.
var align = [16][]int{
	{}, {}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42},
	{6, 26, 46}, {6, 28, 50}, {6, 30, 54}, {6, 32, 58}, {6, 34, 62},
	{6, 26, 46, 66}, {6, 26, 48, 70},
}

func dataCodewords(v int) int {
	b := blocksM[v]
	return b[1]*b[2] + b[3]*b[4]
}

// Encode returns the smallest QR code (level M) holding text in byte mode.
func Encode(text string) (*Code, error) {
	data := []byte(text)
	v := 1
	for ; v <= 15; v++ {
		cc := 8
		if v >= 10 {
			cc = 16
		}
		if 4+cc+8*len(data) <= 8*dataCodewords(v) {
			break
		}
	}
	if v > 15 {
		return nil, ErrTooLong
	}
	return build(v, interleave(v, encodeData(v, data))), nil
}

// encodeData builds the data codewords: mode, length, bytes, terminator and
// padding.
func encodeData(v int, data []byte) []byte {
	var bits []bool
	put := func(val, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, (val>>i)&1 == 1)
		}
	}
	cc := 8
	if v >= 10 {
		cc = 16
	}
	put(0b0100, 4) // byte mode
	put(len(data), cc)
	for _, b := range data {
		put(int(b), 8)
	}
	capBits := 8 * dataCodewords(v)
	for i := 0; i < 4 && len(bits) < capBits; i++ {
		bits = append(bits, false)
	}
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	out := make([]byte, 0, capBits/8)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for j := 0; j < 8; j++ {
			b <<= 1
			if bits[i+j] {
				b |= 1
			}
		}
		out = append(out, b)
	}
	for pad := byte(0xEC); len(out) < capBits/8; pad ^= 0xEC ^ 0x11 {
		out = append(out, pad)
	}
	return out
}

// interleave splits data into blocks, adds Reed-Solomon codewords, and
// interleaves the result as the standard requires.
func interleave(v int, data []byte) []byte {
	b := blocksM[v]
	ecn := b[0]
	var blocks, ecs [][]byte
	for g := 0; g < 2; g++ {
		count, size := b[1+2*g], b[2+2*g]
		for i := 0; i < count; i++ {
			blk := data[:size]
			data = data[size:]
			blocks = append(blocks, blk)
			ecs = append(ecs, rsRemainder(blk, ecn))
		}
	}
	var out []byte
	for i := 0; ; i++ {
		more := false
		for _, blk := range blocks {
			if i < len(blk) {
				out = append(out, blk[i])
				more = true
			}
		}
		if !more {
			break
		}
	}
	for i := 0; i < ecn; i++ {
		for _, ec := range ecs {
			out = append(out, ec[i])
		}
	}
	return out
}

// ---- Reed-Solomon over GF(256), polynomial 0x11D ----

var gfExp [512]byte
var gfLog [256]int

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = i
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[gfLog[a]+gfLog[b]]
}

// rsRemainder returns the n error correction codewords for data.
func rsRemainder(data []byte, n int) []byte {
	gen := []byte{1} // highest degree first
	for i := 0; i < n; i++ {
		next := make([]byte, len(gen)+1)
		for j, c := range gen {
			next[j] ^= c
			next[j+1] ^= gfMul(c, gfExp[i])
		}
		gen = next
	}
	res := make([]byte, len(data)+n)
	copy(res, data)
	for i := range data {
		if c := res[i]; c != 0 {
			for j := 1; j < len(gen); j++ {
				res[i+j] ^= gfMul(gen[j], c)
			}
		}
	}
	return res[len(data):]
}

// ---- matrix ----

type grid struct {
	size    int
	mod, fn []bool // fn marks function patterns, which masks don't touch
}

func (g *grid) set(x, y int, dark bool) {
	g.mod[y*g.size+x] = dark
	g.fn[y*g.size+x] = true
}

func build(v int, codewords []byte) *Code {
	size := 17 + 4*v
	g := &grid{size: size, mod: make([]bool, size*size), fn: make([]bool, size*size)}

	for _, p := range [][2]int{{0, 0}, {size - 7, 0}, {0, size - 7}} {
		for dy := -1; dy <= 7; dy++ {
			for dx := -1; dx <= 7; dx++ {
				x, y := p[0]+dx, p[1]+dy
				if x < 0 || y < 0 || x >= size || y >= size {
					continue
				}
				d := max(abs(dx-3), abs(dy-3))
				g.set(x, y, d != 2 && d != 4)
			}
		}
	}
	for i := 8; i < size-8; i++ {
		g.set(6, i, i%2 == 0)
		g.set(i, 6, i%2 == 0)
	}
	pos := align[v]
	for i, cy := range pos {
		for j, cx := range pos {
			last := len(pos) - 1
			if (i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0) {
				continue // overlaps a finder pattern
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					g.set(cx+dx, cy+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	g.drawFormat(0) // reserve the format areas; redrawn per mask below
	if v >= 7 {
		bits := versionBits(v)
		for i := 0; i < 18; i++ {
			dark := (bits>>i)&1 == 1
			a, b := size-11+i%3, i/3
			g.set(a, b, dark)
			g.set(b, a, dark)
		}
	}

	// Data, in two-column zigzags from the bottom right.
	i := 0
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5 // skip the vertical timing pattern
		}
		for vert := 0; vert < size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = size - 1 - vert
				}
				if !g.fn[y*size+x] && i < len(codewords)*8 {
					g.mod[y*size+x] = (codewords[i>>3]>>(7-i&7))&1 == 1
					i++
				}
			}
		}
	}

	best, bestScore := -1, 0
	var bestMod []bool
	for m := 0; m < 8; m++ {
		t := &grid{size: size, mod: append([]bool(nil), g.mod...), fn: g.fn}
		t.applyMask(m)
		t.drawFormat(m)
		if s := t.penalty(); best < 0 || s < bestScore {
			best, bestScore, bestMod = m, s, t.mod
		}
	}
	return &Code{Size: size, mod: bestMod}
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func (g *grid) applyMask(m int) {
	for y := 0; y < g.size; y++ {
		for x := 0; x < g.size; x++ {
			var flip bool
			switch m {
			case 0:
				flip = (x+y)%2 == 0
			case 1:
				flip = y%2 == 0
			case 2:
				flip = x%3 == 0
			case 3:
				flip = (x+y)%3 == 0
			case 4:
				flip = (x/3+y/2)%2 == 0
			case 5:
				flip = x*y%2+x*y%3 == 0
			case 6:
				flip = (x*y%2+x*y%3)%2 == 0
			case 7:
				flip = ((x+y)%2+x*y%3)%2 == 0
			}
			if flip && !g.fn[y*g.size+x] {
				g.mod[y*g.size+x] = !g.mod[y*g.size+x]
			}
		}
	}
}

// versionBits is the 18-bit version word, drawn for versions 7 and up.
func versionBits(v int) int {
	rem := v
	for i := 0; i < 12; i++ {
		rem = rem<<1 ^ (rem>>11)*0x1F25
	}
	return v<<12 | rem
}

// formatBits is the 15-bit format word for level M and mask m.
func formatBits(m int) int {
	data := 0b00<<3 | m // level M is 00
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	return (data<<10 | rem) ^ 0x5412
}

func (g *grid) drawFormat(m int) {
	bits := formatBits(m)
	bit := func(i int) bool { return (bits>>i)&1 == 1 }
	s := g.size
	for i := 0; i <= 5; i++ {
		g.set(8, i, bit(i))
	}
	g.set(8, 7, bit(6))
	g.set(8, 8, bit(7))
	g.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		g.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		g.set(s-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		g.set(8, s-15+i, bit(i))
	}
	g.set(8, s-8, true) // the dark module
}

// penalty scores a masked grid by the standard's four rules; lower is better.
func (g *grid) penalty() int {
	s := g.size
	at := func(x, y int) bool { return g.mod[y*s+x] }
	score := 0
	for pass := 0; pass < 2; pass++ {
		for a := 0; a < s; a++ {
			run := 1
			var line []bool
			for b := 0; b < s; b++ {
				x, y := b, a
				if pass == 1 {
					x, y = a, b
				}
				line = append(line, at(x, y))
				if b > 0 {
					if line[b] == line[b-1] {
						run++
					} else {
						run = 1
					}
					if run == 5 {
						score += 3
					} else if run > 5 {
						score++
					}
				}
			}
			for b := 0; b+11 <= s; b++ {
				if matches(line[b:b+11], "10111010000") || matches(line[b:b+11], "00001011101") {
					score += 40
				}
			}
		}
	}
	dark := 0
	for y := 0; y < s; y++ {
		for x := 0; x < s; x++ {
			if at(x, y) {
				dark++
			}
			if x < s-1 && y < s-1 {
				c := at(x, y)
				if at(x+1, y) == c && at(x, y+1) == c && at(x+1, y+1) == c {
					score += 3
				}
			}
		}
	}
	score += 10 * (abs(dark*100/(s*s)-50) / 5)
	return score
}

func matches(line []bool, pat string) bool {
	for i, c := range pat {
		if line[i] != (c == '1') {
			return false
		}
	}
	return true
}

// SVG renders the code with the standard 4-module quiet zone. The output is
// built only from numbers, so it's safe to embed in HTML.
func (c *Code) SVG() string {
	n := c.Size + 8
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" class="qr" shape-rendering="crispEdges" role="img" aria-label="QR code">`, n, n)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Dark(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+4, y+4)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}

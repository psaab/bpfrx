package ipsec

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// Portions of the $9$ decoder in this file are adapted from the MIT-licensed
// github.com/nadddy/jcrypt project:
//
// MIT License
// Copyright (c) 2020 nadddy
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

const junosSecretMagic = "$9$"

var errInvalidJunosSecret = errors.New("invalid Junos $9$ secret")

var junosNumAlpha = []byte{}
var junosExtraNum = make([]int, 256)
var junosAlphaNum = make([]int, 256)
var junosEncoding = [][]int{{1, 4, 32}, {1, 16, 32}, {1, 8, 32}, {1, 64}, {1, 32}, {1, 4, 16, 128}, {1, 32, 64}}

func init() {
	family := [][]byte{
		[]byte("QzF3n6/9CAtpu0O"),
		[]byte("B1IREhcSyrleKvMW8LXx"),
		[]byte("7N-dVbwsY2g4oaJZGUDj"),
		[]byte("iHkq.mPf5T"),
	}
	offset := 0
	for i, bs := range family {
		junosNumAlpha = append(junosNumAlpha, bs...)
		for j, b := range bs {
			junosAlphaNum[b] = offset + j
			junosExtraNum[b] = 3 - i
		}
		offset += len(bs)
	}
}

func normalizePSK(secret string) (string, error) {
	if strings.HasPrefix(secret, junosSecretMagic) {
		return decodeJunosSecret(secret)
	}
	return secret, nil
}

func decodeJunosSecret(secret string) (string, error) {
	if !strings.HasPrefix(secret, junosSecretMagic) {
		return "", errInvalidJunosSecret
	}

	rest := []byte(secret[len(junosSecretMagic):])
	if len(rest) == 0 {
		return "", errInvalidJunosSecret
	}

	first := rest[:1]
	rest = rest[1:]

	skip := junosExtraNum[first[0]]
	if skip > len(rest) {
		return "", errInvalidJunosSecret
	}
	rest = rest[skip:]
	prev := first[0]

	out := make([]byte, 0, len(rest))
	for len(rest) > 0 {
		decode := junosEncoding[len(out)%len(junosEncoding)]
		if len(rest) < len(decode) {
			return "", errInvalidJunosSecret
		}
		nibble := rest[:len(decode)]
		rest = rest[len(decode):]

		gaps := make([]byte, 0, len(nibble))
		for _, nb := range nibble {
			gap, err := junosGap(prev, nb)
			if err != nil {
				return "", err
			}
			prev = nb
			gaps = append(gaps, gap)
		}
		out = append(out, junosGapDecode(gaps, decode))
	}

	return string(out), nil
}

func junosGap(prev, next byte) (byte, error) {
	if int(prev) >= len(junosAlphaNum) || int(next) >= len(junosAlphaNum) {
		return 0, errInvalidJunosSecret
	}
	if !bytes.Contains(junosNumAlpha, []byte{prev}) || !bytes.Contains(junosNumAlpha, []byte{next}) {
		return 0, errInvalidJunosSecret
	}
	gap := (junosAlphaNum[next]-junosAlphaNum[prev])%len(junosNumAlpha) - 1
	if gap < 0 {
		gap += len(junosNumAlpha)
	}
	return byte(gap), nil
}

func junosGapDecode(gaps []byte, decode []int) byte {
	num := 0
	for i := range gaps {
		num += int(gaps[i]) * decode[i]
	}
	return byte(num % 256)
}

func sanitizeChildName(name string) string {
	if name == "" {
		return "traffic-selector"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "traffic-selector"
	}
	return out
}

func authMethodToSwan(method string) (string, error) {
	switch method {
	case "", "pre-shared-keys":
		return "psk", nil
	case "rsa-signatures", "ecdsa-signatures":
		return "pubkey", nil
	default:
		return "", fmt.Errorf("unsupported IKE authentication-method %q", method)
	}
}

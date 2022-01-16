// Package totp provides HOTP and TOTP 2FA code generation mechanisms.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"hash"
	"time"
)

// Encodes a uint64 as a big-endian byte slice.
// Manual binary encoding is much faster than using the encoding/binary package.
func encodeUint64(n uint64) []byte {
	buf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		buf[i] = byte((n >> (56 - (i * 8))) & 0xff)
	}
	return buf
}

// Decodes a big-endian uint32 from a byte slice.
// Manual binary decoding is much faster than using the encoding/binary package.
func decodeUint32(buf []byte) (n uint32) {
	for i := 0; i < 4; i++ {
		n += uint32(buf[i]) << ((3 - i) * 8)
	}
	return
}

// Converts an integer to a one-time-password padded to 6 digits.
func stringifyOTP(d uint32) string {
	if d >= 1e6 {
		return "" // Not valid
	}
	return fmt.Sprintf("%06d", d)
}

// GenerateHOTP generates a 6-digit OTP from the given input parameters. If
// hashFunc is nil, GenerateHOTP defaults to using sha1 for the HMAC.
func GenerateHOTP(hashFunc func() hash.Hash, secret []byte, counter uint64) string {
	if hashFunc == nil {
		hashFunc = sha1.New
	}

	w := hmac.New(hashFunc, secret)
	w.Write(encodeUint64(counter))
	digest := w.Sum(nil)
	offset := digest[len(digest)-1] & 0xf
	p := digest[offset : offset+4]
	p[0] &= 0x7f // mask significant bit for sign clarity
	d := decodeUint32(p)
	return stringifyOTP(d % 1e6)
}

// GenerateTOTP generates a 6-digit time-based OTP from the given input
// parameters. If hashFunc is nil, GenerateTOTP defaults to using sha1 for the HMAC.
func GenerateTOTP(hashFunc func() hash.Hash, secret []byte, now time.Time) string {
	counter := uint64(now.Unix() / 30)
	return GenerateHOTP(hashFunc, secret, counter)
}

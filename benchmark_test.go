package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

func BenchmarkGenerateHOTP(b *testing.B) {
	b.Run("GenerateHOTP-sha1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			GenerateHOTP(sha1.New, make([]byte, 20), 0xffff)
		}
	})
	b.Run("GenerateHOTP-sha256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			GenerateHOTP(sha256.New, make([]byte, 32), 0xffff)
		}
	})
	b.Run("GenerateHOTP-sha512", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			GenerateHOTP(sha512.New, make([]byte, 64), 0xffff)
		}
	})
}

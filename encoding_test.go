package totp

import (
	"encoding/hex"
	"testing"
)

func TestEncodeUint64(t *testing.T) {
	type Fixture struct {
		input     uint64
		outputHex string
	}

	fixtures := []*Fixture{
		{0, "0000000000000000"},
		{1, "0000000000000001"},
		{0xff, "00000000000000ff"},
		{0x123, "0000000000000123"},
		{0x123456789abcdef0, "123456789abcdef0"},
		{0x8fffffffffffffff, "8fffffffffffffff"},
		{0xffffffffffffffff, "ffffffffffffffff"},
	}

	for _, fixture := range fixtures {
		encoded := encodeUint64(fixture.input)
		encodedHex := hex.EncodeToString(encoded)
		if encodedHex != fixture.outputHex {
			t.Errorf("failed to encode uint64 %d\nWanted %s\nGot    %s", fixture.input, fixture.outputHex, encodedHex)
		}
	}
}

func TestDecodeUint32(t *testing.T) {
	type Fixture struct {
		inputHex string
		output   uint32
	}

	fixtures := []*Fixture{
		{"00000000", 0},
		{"00000001", 1},
		{"00000012", 0x12},
		{"0000ffff", 0xffff},
	}

	for _, fixture := range fixtures {
		data, _ := hex.DecodeString(fixture.inputHex)
		n := decodeUint32(data)
		if n != fixture.output {
			t.Errorf("Failed to decode uint32 %d; Got %d", fixture.output, n)
		}
	}
}

func TestStringifyOTP(t *testing.T) {
	type Fixture struct {
		input  uint32
		output string
	}

	fixtures := []*Fixture{
		{0, "000000"},
		{1, "000001"},
		{11, "000011"},
		{121, "000121"},
		{1234, "001234"},
		{12345, "012345"},
		{123456, "123456"},
		{1000000, ""},
	}

	for _, fixture := range fixtures {
		output := stringifyOTP(fixture.input)
		if output != fixture.output {
			t.Errorf("Failed to stringify 6-digit OTP\nWanted %s\nGot    %s", fixture.output, output)
		}
	}
}

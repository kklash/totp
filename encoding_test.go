package totp

import (
	"testing"
)

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

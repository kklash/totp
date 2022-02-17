package totp_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"testing"
	"time"

	"github.com/kklash/totp"
)

func TestGenerateTOTP(t *testing.T) {
	type Fixture struct {
		counter   uint64
		hashFunc  func() hash.Hash
		secretHex string
		otp       string
	}

	fixtures := []*Fixture{
		// RFC4226 Vectors
		// https://tools.ietf.org/html/rfc4226#appendix-D
		{
			counter:   0,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "755224",
		},
		{
			counter:   1,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "287082",
		},
		{
			counter:   2,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "359152",
		},
		{
			counter:   3,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "969429",
		},
		{
			counter:   4,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "338314",
		},
		{
			counter:   5,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "254676",
		},
		{
			counter:   6,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "287922",
		},
		{
			counter:   7,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "162583",
		},
		{
			counter:   8,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "399871",
		},
		{
			counter:   9,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "520489",
		},

		// RFC6238 test vectors
		// https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
		{
			counter:   1,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "287082",
		},
		{
			hashFunc:  sha256.New,
			counter:   1,
			secretHex: "3132333435363738393031323334353637383930313233343536373839303132",
			otp:       "119246",
		},
		{
			hashFunc:  sha512.New,
			counter:   1,
			secretHex: "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334",
			otp:       "693936",
		},
		{
			counter:   0x23523EC,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "081804",
		},
		{
			hashFunc:  sha256.New,
			counter:   0x23523EC,
			secretHex: "3132333435363738393031323334353637383930313233343536373839303132",
			otp:       "084774",
		},
		{
			hashFunc:  sha512.New,
			counter:   0x23523EC,
			secretHex: "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334",
			otp:       "091201",
		},
		{
			counter:   0x23523ED,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "050471",
		},
		{
			hashFunc:  sha256.New,
			counter:   0x23523ED,
			secretHex: "3132333435363738393031323334353637383930313233343536373839303132",
			otp:       "062674",
		},
		{
			hashFunc:  sha512.New,
			counter:   0x23523ED,
			secretHex: "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334",
			otp:       "943326",
		},
		{
			counter:   0x273EF07,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "005924",
		},
		{
			hashFunc:  sha256.New,
			counter:   0x273EF07,
			secretHex: "3132333435363738393031323334353637383930313233343536373839303132",
			otp:       "819424",
		},
		{
			hashFunc:  sha512.New,
			counter:   0x273EF07,
			secretHex: "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334",
			otp:       "441116",
		},
		{
			counter:   0x3F940AA,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "279037",
		},
		{
			hashFunc:  sha256.New,
			counter:   0x3F940AA,
			secretHex: "3132333435363738393031323334353637383930313233343536373839303132",
			otp:       "698825",
		},
		{
			hashFunc:  sha512.New,
			counter:   0x3F940AA,
			secretHex: "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334",
			otp:       "618901",
		},
		{
			counter:   0x27BC86AA,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "353130",
		},
		{
			hashFunc:  sha256.New,
			counter:   0x27BC86AA,
			secretHex: "3132333435363738393031323334353637383930313233343536373839303132",
			otp:       "737706",
		},
		{
			hashFunc:  sha512.New,
			counter:   0x27BC86AA,
			secretHex: "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334",
			otp:       "863826",
		},

		// Google Authenticator tests
		{
			counter:   1111111111 / 30,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "050471",
		},
		{
			counter:   1234567890 / 30,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "005924",
		},
		{
			counter:   2000000000 / 30,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "279037",
		},
		{
			hashFunc:  sha256.New,
			counter:   1111111111 / 30,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "584430",
		},
		{
			hashFunc:  sha256.New,
			counter:   1234567890 / 30,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "829826",
		},
		{
			hashFunc:  sha256.New,
			counter:   2000000000 / 30,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "428693",
		},
		{
			hashFunc:  sha512.New,
			counter:   1111111111 / 30,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "380122",
		},
		{
			hashFunc:  sha512.New,
			counter:   1234567890 / 30,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "671578",
		},
		{
			hashFunc:  sha512.New,
			counter:   2000000000 / 30,
			secretHex: "3132333435363738393031323334353637383930",
			otp:       "464532",
		},

		// Randomly generated test vectors
		{
			counter:   0xb7ef2ffd0ceb683,
			secretHex: "2118fda0080ebe9b0a13569e67f6d29614f22c48",
			otp:       "999792",
		},
		{
			counter:   0x47e403947b64c956,
			secretHex: "567accda6f72573108058f0d128378f34c022ae8",
			otp:       "964457",
		},
		{
			counter:   0xd41e1fe274a2eae9,
			secretHex: "6d1b64ac8343ced5f682bcb1af956cb57e31dc45",
			otp:       "662857",
		},
		{
			counter:   0x382254b4330ffc3d,
			secretHex: "1bec76a5524b7cbd853b8336f37969dc18c060a3",
			otp:       "721892",
		},
		{
			counter:   0xeb5d7526aee38e02,
			secretHex: "f1fdd457b35ebfb142be9e520711353433e876b3",
			otp:       "770899",
		},
		{
			counter:   0xd8f3db69d9e00e0a,
			secretHex: "a7f65d01ef3e996ccfd92afb0b289f90a904b019",
			otp:       "974879",
		},
		{
			counter:   0x390f0939f1333549,
			secretHex: "b92a041ada34da9a85197046933e20bbc2a14b6a",
			otp:       "780119",
		},
	}

	for _, fixture := range fixtures {
		secret, _ := hex.DecodeString(fixture.secretHex)
		generated := totp.GenerateHOTP(fixture.hashFunc, secret, fixture.counter)
		if generated != fixture.otp {
			t.Errorf("failed to generate otp with counter 0x%x\nWanted %s\nGot    %s", fixture.counter, fixture.otp, generated)
		}
	}
}

func ExampleGenerateHOTP() {
	secret := []byte("12345678901234567890")
	var counter uint64 = 1
	otp1 := totp.GenerateHOTP(nil, secret, counter)
	fmt.Println(otp1)

	// output:
	// 287082
}

func ExampleGenerateTOTP() {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)

	otp2 := totp.GenerateTOTP(nil, secret, now)
	fmt.Println(otp2)

	// output:
	// 050471
}

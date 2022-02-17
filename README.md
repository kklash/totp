# TOTP

This package provides a performant no-nonsense zero-dep implementation of the one-time password algorithms specified in [RFC4226](https://datatracker.ietf.org/doc/html/rfc4226) and [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238).

```go
package main

import (
  "fmt"
  "time"

  "github.com/kklash/totp"
)

func main() {
  secret := []byte("12345678901234567890")

  // Generate OTPs based on a counter.
  var counter uint64 = 1
  otp1 := totp.GenerateHOTP(nil, secret, counter)
  fmt.Println(otp1) // 287082

  // Generate OTPs based on the current time, divided into
  // time steps of 30 seconds to get the counter.
  now := time.Unix(1111111111, 0)
  otp2 := totp.GenerateTOTP(nil, secret, now)
  fmt.Println(otp2) // 050471
}
```

# Status

Not ready for production yet 

# What?

A module which you can plug in your http request to force your json request come with otp verification

# How to use

##### ENV:

envs are declared in [env.go](env.go)

##### Code:

```
import kotp "github.com/kanguki/otp"
type yourHttpDriver struct {
	otpDriver kotp.Driver
	mux  *http.ServeMux
}
func main() {
	cipherDriver = NewCipherDriver(CipherDriverConfig{
		PrivatePemFilePath: absPrivateKeyPath,
		PublicPemFilePath: absPublicKeyPath,
		Ttl: 1,
		OtpLength: 4,
		OtpValueType: NUMBER,
	})
	otpDriver := &cipherDriver 
	mux := http.NewServeMux()
	mux.HandleFunc("/new/otp", func(w http.ResponseWriter, r *http.Request) {
		key, val, _ := otpDriver.GenOtp()
		//send notification containing otp value, then return key
	`	w.Write([]byte(key))
	})
	var yourRealHandler http.HandlerFunc
	mux.HandleFunc("/your/api", otpDriver.VerifyOtp(yourRealHandler))
	d := yourHttpDriver{otpDriver: otpDriver, mux: mux}
}
```

# Run

```
chmod 765 */*.sh
```

Run tests

```
./test.sh
```

# TODO

###### Invalidate cipher otp after verification.

This might involves some place to save. But my intention is making it as dependent as possible from external network calls. Hmmmmmm. Might come back when I have time :D

/**
* Cryptography fits this case well!
* Usage:
* - Step1: Server GenOtp returns otpK, otpV, Client can see otpK
* - (Notify client about otpV)
* - Step2: Client calls request with response body contains fields (otpK, otpV)
 */

package otp

import (
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"

	"github.com/kanguki/log"
	"github.com/kanguki/otp/cipher"
)

type Driver interface {
	GenOtp() (k, v string, e error)
	VerifyOtp(http.HandlerFunc) http.HandlerFunc
}

type CipherDriver struct {
	CipherDriverConfig
}
type CipherDriverConfig struct {
	PrivatePemFilePath string
	PublicPemFilePath  string
	// secret       string //used if sslFilePath is missing //not used now
	Ttl          int //time to live in minute
	OtpValueType     //used to generate value. default NUMBER
	OtpLength    int //default 4
}
type OtpValueType int

const (
	STRING OtpValueType = iota
	NUMBER
	MIXED //mixed string and number
)
const timeFormat = "20060102150405"

func NewCipherDriver(conf CipherDriverConfig) CipherDriver {
	return CipherDriver{CipherDriverConfig: conf}
}

func (d *CipherDriver) GenOtp() (k, v string, err error) {
	return d.genOtpWithExpire()
}

//for flexibly generating otp with expiration
func (d *CipherDriver) genOtpWithExpire(expiredAt ...time.Time) (k, v string, err error) {
	otp := d.genOtp()
	var exp time.Time
	if len(expiredAt) != 1 {
		exp = time.Now().UTC().Add(time.Minute * time.Duration(d.Ttl))
	} else {
		exp = expiredAt[0]
	}
	signed, err := cipher.RSA_Encrypt([]byte(otp+exp.Format(timeFormat)), d.PublicPemFilePath)
	if err != nil {
		return "", "", err
	}
	return signed, otp, err
}

type Otp struct {
	Key   string `json:"otpK"`
	Value string `json:"otpV"`
}

func (d *CipherDriver) VerifyOtp(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Log("verifying otp")
		// Read body
		b, err := ioutil.ReadAll(r.Body)
		defer r.Body.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Unmarshal
		var otp Otp
		err = json.Unmarshal(b, &otp)
		if err != nil {
			log.Log(err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if otp.Key == "" || otp.Value == "" {
			log.Log("empty otp: %+v", otp)
			http.Error(w, "empty otp", http.StatusUnauthorized)
			return
		}

		log.Log("key: %v, value: %v", otp.Key, otp.Value)
		//decrypt and compare time/value
		keyB, err := cipher.RSA_Decrypt([]byte(otp.Key), d.PrivatePemFilePath)
		key := string(keyB)
		if err != nil || len(key) != d.OtpLength+14 { //14 is length of 20060102150405
			log.Log("error decrypting otp: %v", err)
			http.Error(w, "invalid otp", http.StatusBadRequest)
			return
		}
		expiredAt, err := time.Parse(timeFormat, key[d.OtpLength:d.OtpLength+14])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if time.Now().UTC().After(expiredAt) {
			log.Log("otp expired at %v", expiredAt)
			http.Error(w, "otp expired", http.StatusBadRequest)
			return
		}
		if key[:d.OtpLength] != otp.Value {
			log.Log("incorrect otp %v", otp.Value)
			http.Error(w, "incorrect otp", http.StatusBadRequest)
			return
		}
		next(w, r)
	}
}

func (d *CipherDriver) genOtp() string {
	return genRandomOfLength(d.OtpValueType, d.OtpLength)
}

//generate random string
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const numBytes = "0123456789" //default
const mixedBytes = letterBytes + numBytes

func genRandomOfLength(t OtpValueType, length int) string {
	rand.Seed(time.Now().UTC().UnixNano()) //if this is missed, rand will not be random :D
	if length <= 0 {
		length = 4
	}
	b := make([]byte, length)
	var dictionary string
	switch t {
	case STRING:
		dictionary = letterBytes
	case MIXED:
		dictionary = mixedBytes
	default:
		dictionary = numBytes
	}
	for i := range b {
		b[i] = dictionary[rand.Intn(len(dictionary))]
	}
	return string(b)
}

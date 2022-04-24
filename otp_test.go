package otp

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"
)

var d Driver
var cipherDriver CipherDriver

func TestMain(m *testing.M) {
	absPrivateKeyPath, err := filepath.Abs("keys/private.pem")
	if err != nil {
		log.Fatal(err)
	}
	absPublicKeyPath, err := filepath.Abs("keys/public.pem")
	if err != nil {
		log.Fatal(err)
	}
	cipherDriver = NewCipherDriver(CipherDriverConfig{
		PrivatePemFilePath: absPrivateKeyPath,
		PublicPemFilePath:  absPublicKeyPath,
		Ttl:                1,
		OtpLength:          4,
		OtpValueType:       NUMBER,
	})
	d = &cipherDriver
	m.Run()
}

func TestGenRandom(t *testing.T) {
	a, b := genRandomOfLength(MIXED, 4), genRandomOfLength(MIXED, 4)
	assert.NotEqual(t, a, b)
	t.Log(a, b)
}

func TestGenOtp(t *testing.T) {
	signed, otp, err := d.GenOtp()
	assert.NoError(t, err)
	t.Logf("otp: %v, key: %v\n", otp, signed)
}

func TestVerifyOtp(t *testing.T) {
	router := httprouter.New()
	router.POST("/", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		d.VerifyOtp(func(ww http.ResponseWriter, rr *http.Request) {
			ww.Write([]byte("ok"))
		})(w, r)
	})
	signed, otp, _ := d.GenOtp()
	{
		recorder := httptest.NewRecorder()
		body := strings.NewReader(fmt.Sprintf(`{"otpK":"%v","otpV":"%v","data":"random data"}`, signed, otp))
		request, _ := http.NewRequest(http.MethodPost, "/", body)
		router.ServeHTTP(recorder, request)
		assert.Equal(t, http.StatusOK, recorder.Code)
	}
	{
		recorder := httptest.NewRecorder()
		body := strings.NewReader(`{"data":"random data"}`)
		request, _ := http.NewRequest(http.MethodPost, "/", body)
		router.ServeHTTP(recorder, request)
		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	}
	{
		recorder := httptest.NewRecorder()
		body := strings.NewReader(fmt.Sprintf(`{"otpK":"%v","otpV":"sdsf","data":"random data"}`, signed))
		request, _ := http.NewRequest(http.MethodPost, "/", body)
		router.ServeHTTP(recorder, request)
		assert.Equal(t, http.StatusBadRequest, recorder.Code)
	}
	{
		recorder := httptest.NewRecorder()
		body := strings.NewReader(`{"otpK":"HA5x8eDsp8iotTA8bXvBOI1o6QNlg+dpyNDr3oPi6O3+/EzPMxFIOa9NvX0HfsATUfnAHPuRN6FLOvtSuv1Z+Q==","otpV":"8338","data":"random data"}`)
		request, _ := http.NewRequest(http.MethodPost, "/", body)
		router.ServeHTTP(recorder, request)
		assert.Equal(t, http.StatusBadRequest, recorder.Code)
	}
	{
		expiredKey, otp, _ := cipherDriver.genOtpWithExpire(time.Now().UTC().Add(-time.Minute))
		recorder := httptest.NewRecorder()
		body := strings.NewReader(fmt.Sprintf(`{"otpK":"%v","otpV":"%v","data":"random data"}`, expiredKey, otp))
		request, _ := http.NewRequest(http.MethodPost, "/", body)
		router.ServeHTTP(recorder, request)
		assert.Equal(t, http.StatusBadRequest, recorder.Code)
	}
}

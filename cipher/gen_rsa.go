/**
* reference: https://developpaper.com/how-to-implement-rsa-encryption-and-decryption-in-go-language/
 */
package cipher

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

const (
	privatePemPath = "keys/private.pem" //replace with what you want
	publicPemPath  = "keys/public.pem"
)

//Generate RSA private key and public key and save them to a file
func GenerateRSAKey(bits int) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	//Save private key
	//Serialize the obtained rsa private key into der encoded string of ASN. 1 through x509 standard
	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	privateFile, err := os.Create(privatePemPath)
	if err != nil {
		panic(err)
	}
	defer privateFile.Close()
	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}
	pem.Encode(privateFile, &privateBlock)
	//Save public key
	publicKey := privateKey.PublicKey
	//X509 encoding public key
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	publicFile, err := os.Create(publicPemPath)
	if err != nil {
		panic(err)
	}
	defer publicFile.Close()
	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}
	//Save to file
	pem.Encode(publicFile, &publicBlock)
}

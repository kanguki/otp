/***
* * reference: https://developpaper.com/how-to-implement-rsa-encryption-and-decryption-in-go-language/
 */
package cipher

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
)

//RSA encryption
func RSA_Encrypt(plainText []byte, path string) (string, error) {
	//Open file
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	//Read the contents of the file
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//PEM decoding
	block, _ := pem.Decode(buf)
	//X509 decoding
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	//Type assertion
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	//Encrypt plaintext
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		return "", err
	}
	return encode(cipherText), nil
	//return cipherText
}

//RSA decryption
func RSA_Decrypt(cipherText []byte, path string) ([]byte, error) {
	//Open file
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	//Get file content
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//PEM decoding
	block, _ := pem.Decode(buf)
	//X509 decoding
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	cipherText, err = decode(string(cipherText))
	if err != nil {
		return nil, err
	}
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	return plainText, nil
}

//encode to base64 for readability
func encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
func decode(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return data, nil
}

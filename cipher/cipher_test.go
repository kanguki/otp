package cipher

import (
	"testing"
)

func TestEncryptDecryptMessage(t *testing.T) {
	// GenerateRSAKey(256) //512 1024 2048 //skip if already exist to make test run faster
	message := []byte("hello world1231231234") //max 21 for 256
	//Encryption
	ciphertext, err := RSA_Encrypt(message, publicPemPath)
	if err != nil {
		t.Errorf("error encrypting message %v", err)
	}
	t.Log("encrypted as:", string(ciphertext))
	//Decryption
	plaintext, err := RSA_Decrypt([]byte(ciphertext), privatePemPath)
	if err != nil {
		t.Errorf("error decrypting message %v", err)
	}
	t.Log("decrypted as:", string(plaintext))
}

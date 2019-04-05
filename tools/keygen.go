// Ideas from:
// https://gist.githubusercontent.com/devinodaniel/8f9b8a4f31573f428f29ec0e884e6673/raw/d4d4495db6fcc6cce367c11a6f70ccfb65ba36a9/gistfile1.txt

//
// keygen.go -bits 4096  -pass "hello" -pkfile /tmp/agentx.pk -pkfile-b64 /tmp/agentx.bpk -pubfile /tmp/agentx.pub
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func main() {


	var (
		pkFile string
		pkFileB64 string
		pubFile string
		passphrase string
		bitSize *int
	)

	flag.StringVar(&pkFile, "pkfile", "/dev/null", "PK file path")
	flag.StringVar(&pubFile, "pubfile", "/dev/null", "PUB file path")
	flag.StringVar(&pkFileB64, "pkfile-b64", "/dev/null", "PK B64 file path")
	flag.StringVar(&passphrase, "pass", "/dev/null", "Passphrase for PK")
	bitSize = flag.Int("bits", 4096, "RSA bit size (default: 4096)")


	flag.Parse()

	fmt.Printf("[+] Generating PK\n")
	privateKey, err := generatePrivateKey(*bitSize)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Printf("[+] Generating PUB from PK (SSH pub)\n")
	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Printf("[+] Encoding PK to PEM\n")
	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	fmt.Printf("[+] Writing PK to file: %s \n", pkFile)
	err = writeKeyToFile(privateKeyBytes, pkFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Printf("[+] Writing PUB to file: %s \n", pubFile)
	err = writeKeyToFile(publicKeyBytes, pubFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Printf("[+] Encrypting PK with passphrase (transmission/storage)\n")
	// PK to BIN
	ciphertext := encBytes(privateKeyBytes, passphrase)
	// fmt.Printf("[*] PK (HEX) : [%x]... \n", ciphertext[:80])

	// BIN to B64
	fmt.Printf("[+] Encoding PK B64 armored PK (transmission)\n")
	ciphertextB64 := base64.StdEncoding.EncodeToString([]byte(ciphertext))
	// fmt.Printf("[*] PK (B64) : [%s]... \n", ciphertextB64[:80])

	// Save PK to File
	fmt.Printf("[+] Saving B64 armored PK to file: %s\n", pkFileB64)
	writeKeyToFile([]byte(ciphertextB64), pkFileB64)
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println("Private Key generated")
	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// generatePublicKey takes a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	log.Println("Public key generated")
	return pubKeyBytes, nil
}

// writeKeyToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	log.Printf("Key saved to: %s", saveFileTo)
	return nil
}

// strToHash hashes a string
func strHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

// encBytes encrypts data with passphrase
func encBytes(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(strHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decBytes(data []byte, passphrase string) []byte {
	key := []byte(strHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encBinToFile(filename string, data []byte, passphrase string) {
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(encBytes(data, passphrase))
}

func decBinFromFile(filename string, passphrase string) []byte {
	data, _ := ioutil.ReadFile(filename)
	return decBytes(data, passphrase)
}

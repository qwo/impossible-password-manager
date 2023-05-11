package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

type PasswordManager struct {
	masterPassword string
}

func NewPasswordManager(masterPassword string) *PasswordManager {
	return &PasswordManager{masterPassword: masterPassword}
}

func (pm *PasswordManager) encrypt(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(pm.masterPassword))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (pm *PasswordManager) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(pm.masterPassword))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, err
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (pm *PasswordManager) SavePassword(service, username, password string) error {
	encryptedPassword, err := pm.encrypt([]byte(password))
	if err != nil {
		return err
	}
	entry := service + ":" + username + ":" + hex.EncodeToString(encryptedPassword) + "\n"
	f, err := os.OpenFile("passwords.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.WriteString(entry); err != nil {
		return err
	}
	return nil
}

func (pm *PasswordManager) GetPassword(service, username string) (string, error) {
	data, err := ioutil.ReadFile("passwords.txt")
	if err != nil {
		return "", err
	}
	decryptedData, err := pm.decrypt(data)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(decryptedData), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		if parts[0] == service && parts[1] == username {
			encryptedPassword, err := hex.DecodeString(parts[2])
			if err != nil {
				return "", err
			}
			decryptedPassword, err := pm.decrypt(encryptedPassword)
			if err != nil {
				return "", err
			}
			return string(decryptedPassword), nil
		}
	}
	return "", fmt.Errorf("password not found")
}

func (pm *PasswordManager) DeletePassword(service, username string) error {
	data, err := ioutil.ReadFile("passwords.txt")
	if err != nil {
		return err
	}
	decryptedData, err := pm.decrypt(data)
	if err != nil {
		return err
	}
	lines := strings.Split(string(decryptedData), "\n")
	var newLines []string
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		if parts[0] == service && parts[1] == username {
			// Skip this line
			continue
		}
		newLines = append(newLines, line)
	}
	newData, err := pm.encrypt([]byte(strings.Join(newLines, "\n")))
	if err != nil {
		return err
	}
	return ioutil.WriteFile("passwords.txt", newData, 0644)
}

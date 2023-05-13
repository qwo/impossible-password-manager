package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

type PasswordManager struct {
	masterPassword string
	vaultPath      string
	data           []byte
}

func NewPasswordManager(masterPassword, vaultPath string) (*PasswordManager, error) {
	encryptedData, err := ioutil.ReadFile(vaultPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	pm := &PasswordManager{
		masterPassword: masterPassword,
		vaultPath:      vaultPath,
	}
	if err == nil {
		pm.data, err = pm.decrypt(encryptedData)
		if err != nil {
			return nil, err
		}
	}
	return pm, nil
}

func (pm *PasswordManager) InitVault() error {
	// Create an empty, encrypted file
	encryptedData, err := pm.encrypt([]byte{})
	if err != nil {
		return err
	}
	return ioutil.WriteFile(pm.vaultPath, encryptedData, 0644)
}

func (pm *PasswordManager) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(pm.masterPassword)) /// handle Error
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
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
		return nil, errors.New("ciphertext too short")
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
	pm.data = append(pm.data, []byte(entry)...)
	encryptedData, err := pm.encrypt(pm.data)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(pm.vaultPath, encryptedData, 0644)
}

func (pm *PasswordManager) GetPassword(service, username string) (string, error) {
	lines := strings.Split(string(pm.data), "\n")
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
	return "", errors.New("password not found")
}

func (pm *PasswordManager) DeletePassword(service, username string) error {
	lines := strings.Split(string(pm.data), "\n")
	for i, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		if parts[0] == service && parts[1] == username {
			// Remove the entry from the data
			lines = append(lines[:i], lines[i+1:]...)
			pm.data = []byte(strings.Join(lines, "\n"))
			// Write the updated data back to the file
			encryptedData, err := pm.encrypt(pm.data)
			if err != nil {
				return err
			}
			return ioutil.WriteFile(pm.vaultPath, encryptedData, 0644)
		}
	}
	return errors.New("password not found")
}

func NewEmptyPasswordManager(masterPassword, vaultPath string) *PasswordManager {
	return &PasswordManager{
		masterPassword: masterPassword,
		vaultPath:      vaultPath,
		data:           []byte{},
	}
}

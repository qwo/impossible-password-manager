package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"sync"
)

// PasswordManager represents a password manager.
type PasswordManager struct {
	masterPassword string
	vaultPath      string
	passwords      map[string]map[string]string
	mu             sync.RWMutex
}

// NewPasswordManager creates a new instance of PasswordManager.
func NewPasswordManager(masterPassword, vaultPath string) (*PasswordManager, error) {
	return &PasswordManager{
		masterPassword: masterPassword,
		vaultPath:      vaultPath,
		passwords:      make(map[string]map[string]string),
	}, nil
}

// InitVault initializes the password vault.
func (pm *PasswordManager) InitVault() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if the vault file already exists
	_, err := ioutil.ReadFile(pm.vaultPath)
	if err == nil {
		return fmt.Errorf("vault file already exists")
	}

	// Create an empty vault
	return pm.saveVault()
}

// SavePassword saves a password for a given service and username.
func (pm *PasswordManager) SavePassword(service, username, password string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if the website exists in the password manager
	websiteData, ok := pm.passwords[service]
	if !ok {
		// Website does not exist, create a new inner map for the website
		websiteData = make(map[string]string)
		pm.passwords[service] = websiteData
	}

	// Save the password for the user
	websiteData[username] = password

	return pm.saveVault()
}

// GetPassword retrieves a password for a given service and username.
func (pm *PasswordManager) GetPassword(service, username string) (string, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Check if the website exists in the password manager
	websiteData, ok := pm.passwords[service]
	if !ok {
		return "", fmt.Errorf("password not found")
	}

	// Retrieve the password for the user
	password, ok := websiteData[username]
	if !ok {
		return "", fmt.Errorf("password not found")
	}

	return password, nil
}

// DeletePassword deletes a password for a given service and username.
func (pm *PasswordManager) DeletePassword(service, username string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if the website exists in the password manager
	websiteData, ok := pm.passwords[service]
	if !ok {
		return fmt.Errorf("password not found")
	}

	// Delete the password for the user
	delete(websiteData, username)

	return pm.saveVault()
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

// saveVault saves the password vault to the vault file.
func (pm *PasswordManager) saveVault() error {
	data, err := json.Marshal(pm.passwords)
	if err != nil {
		return err
	}

	encryptedData, err := pm.encrypt(data)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(pm.vaultPath, encryptedData, 0644)
}

// loadVault loads the password vault from the vault file.
func (pm *PasswordManager) loadVault() error {
	data, err := ioutil.ReadFile(pm.vaultPath)
	if err != nil {
		return err
	}

	decryptedData, err := decrypt(data, pm.masterPassword)
	if err != nil {
		return err
	}

	err = json.Unmarshal(decryptedData, &pm.passwords)
	if err != nil {
		return err
	}

	return nil
}

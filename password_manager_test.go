package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"testing"
	"time"
)

func NewEmptyPasswordManager(masterPassword, vaultPath string) *PasswordManager {
	return &PasswordManager{
		masterPassword: masterPassword,
		vaultPath:      vaultPath,
		passwords:      make(map[string]map[string]string),
	}
}

func TestEncryptDecrypt(t *testing.T) {
	masterPassword := "0123456789ABCDEF"
	vaultName := "pm_vault_test"
	pm := NewEmptyPasswordManager(masterPassword, vaultName)
	defer os.Remove(vaultName)
	data := []byte(masterPassword)

	encryptedData, err := pm.encrypt(data)
	if err != nil {
		t.Errorf("Error encrypting data: %v", err)
	}

	decryptedData, err := pm.decrypt(encryptedData)
	if err != nil {
		t.Errorf("Error decrypting data: %v", err)
	}

	if string(decryptedData) != string(data) {
		t.Errorf("Decrypted data does not match original data")
	}
}

func TestSaveGetDeletePassword_first(t *testing.T) {
	masterPassword := "0123456789ABCDEF"
	vaultName := "pm_vault_test"
	pm := NewEmptyPasswordManager(masterPassword, vaultName)
	defer os.Remove(vaultName)
	service := "google.com"
	username := "myusername"
	password := "mypassword"

	err := pm.InitVault()
	if err != nil {
		t.Fatalf("Error initializing vault: %v", err)
	}

	err = pm.SavePassword(service, username, password)
	if err != nil {
		t.Fatalf("Error saving password: %v", err)
	}

	retrievedPassword, err := pm.GetPassword(service, username)
	if err != nil {
		t.Fatalf("Error getting password: %v", err)
	}

	if retrievedPassword != password {
		t.Errorf("Retrieved password does not match the original password")
	}

	err = pm.DeletePassword(service, username)
	if err != nil {
		t.Fatalf("Error deleting password: %v", err)
	}

	_, err = pm.GetPassword(service, username)
	if err == nil {
		t.Errorf("Password was not deleted successfully")
	}
}

func TestSaveGetDeletePassword_Multiple(t *testing.T) {
	masterPassword := "0123456789ABCDEF"
	pm := NewEmptyPasswordManager(masterPassword, "pm_vault_test")

	err := pm.InitVault()
	if err != nil {
		t.Fatalf("Error initializing vault: %v", err)
	}

	// Save passwords for different services and usernames
	passwords := map[string]map[string]string{
		"google.com": {
			"john": "password1",
			"jane": "password2",
		},
		"facebook.com": {
			"john": "password3",
			"jane": "password4",
		},
		"twitter.com": {
			"john": "password5",
			"jane": "password6",
		},
	}

	// Save passwords
	for service, userData := range passwords {
		for username, password := range userData {
			err := pm.SavePassword(service, username, password)
			if err != nil {
				t.Errorf("Error saving password: %v", err)
			}
		}
	}

	// Retrieve and verify passwords
	for service, userData := range passwords {
		for username, password := range userData {
			retrievedPassword, err := pm.GetPassword(service, username)
			if err != nil {
				t.Errorf("Error getting password: %v", err)
			}

			if retrievedPassword != password {
				t.Errorf("Retrieved password does not match the original password")
			}
		}
	}

	// Delete passwords
	for service, userData := range passwords {
		for username := range userData {
			err := pm.DeletePassword(service, username)
			if err != nil {
				t.Errorf("Error deleting password: %v", err)
			}
		}
	}

	// Verify that passwords were deleted
	for service, userData := range passwords {
		for username := range userData {
			_, err := pm.GetPassword(service, username)
			if err == nil {
				t.Errorf("Password for service '%s' and username '%s' was not deleted", service, username)
			}
		}
	}

	// Verify that deleted passwords do not exist
	for service, userData := range passwords {
		for username := range userData {
			_, err := pm.GetPassword(service, username)
			if err == nil {
				t.Errorf("Password for service '%s' and username '%s' still exists after deletion", service, username)
			}
		}
	}
}

///** alternative stub style

type TestPasswordManagerState struct {
	MasterPassword string
	VaultPath      string
	Passwords      map[string]map[string]string
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	rand.Seed(time.Now().UnixNano())

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b)
}

func setupTestPasswordManager(state TestPasswordManagerState) (*PasswordManager, func()) {
	// Create a temporary vault file
	tempVaultFile, err := ioutil.TempFile("", "vault_*.json")
	if err != nil {
		log.Fatalf("Error creating temporary vault file: %v", err)
	}
	defer os.Remove(tempVaultFile.Name()) // Clean up the temporary file

	// Generate the VaultPath suffix
	vaultPathSuffix := fmt.Sprintf("_%s", randomString(8))

	// Create the PasswordManager with the temporary vault file and generated suffix
	vaultPath := state.VaultPath + vaultPathSuffix
	pm := NewEmptyPasswordManager(state.MasterPassword, vaultPath)

	if err != nil {
		log.Fatalf("Error initializing vault: %v", err)
	}

	// Save passwords
	for service, userData := range state.Passwords {
		for username, password := range userData {
			err := pm.SavePassword(service, username, password)
			if err != nil {
				log.Fatalf("Error saving password: %v", err)
			}
		}
	}

	// Cleanup function to remove the vault file
	cleanup := func() {
		err := os.Remove(vaultPath)
		if err != nil {
			log.Fatalf("Error removing vault file: %v", err)
		}
	}

	// Use defer to automatically clean up the vault file
	return pm, cleanup
}

func TestSaveGetDeletePassword(t *testing.T) {
	state := TestPasswordManagerState{
		MasterPassword: "0123456789ABCDEF",
		VaultPath:      "pm_vault_test",
		Passwords: map[string]map[string]string{
			"google.com": {
				"john": "password1",
				"jane": "password2",
			},
			"facebook.com": {
				"john": "password3",
				"jane": "password4",
			},
			"twitter.com": {
				"john": "password5",
				"jane": "password6",
			},
		},
	}

	pm, cleanup := setupTestPasswordManager(state)
	defer cleanup()

	// Test SavePassword
	service := "google.com"
	username := "john"
	password := "newpassword"

	err := pm.SavePassword(service, username, password)
	if err != nil {
		t.Fatalf("Error saving password: %v", err)
	}

	// Test GetPassword
	retrievedPassword, err := pm.GetPassword(service, username)
	if err != nil {
		t.Fatalf("Error getting password: %v", err)
	}

	if retrievedPassword != password {
		// log.Fatalf(retrievedPassword, err)
		t.Errorf("Retrieved password does not match the expected value")
	}

	// Test DeletePassword
	err = pm.DeletePassword(service, username)
	if err != nil {
		t.Fatalf("Error deleting password: %v", err)
	}

	// Verify that password was deleted
	_, err = pm.GetPassword(service, username)
	if err == nil {
		t.Errorf("Password was not deleted successfully")
	}
}

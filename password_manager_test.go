package main

import (
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	masterPassword := "0123456789ABCDEF"
	pm := NewEmptyPasswordManager(masterPassword, "pm_vault_test")

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

func TestSaveGetDeletePassword(t *testing.T) {
	masterPassword := "0123456789ABCDEF"
	pm := NewEmptyPasswordManager(masterPassword, "pm_vault_test")

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

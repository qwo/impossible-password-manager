package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

var masterPassword, filePath string

var rootCmd = &cobra.Command{
	Use:   "mypasswordmanager",
	Short: "A simple password manager",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// TODO: Prompt the user for the master password
		masterPassword = "myMasterPassword"

		// Check for the file-path flag
		if filePath == "" {
			// Use a default file path if the flag is not set
			filePath = "pm_vault"
		}
	},
}

var addCmd = &cobra.Command{
	Use:   "add [service] [username] [password]",
	Short: "Add a new password",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		service := args[0]
		username := args[1]
		password := args[2]

		pm, err := NewPasswordManager(masterPassword, "vault.file")
		if err != nil {
			fmt.Println("Error initializing password manager:", err)
			return
		}
		err = pm.SavePassword(service, username, password)
		if err != nil {
			fmt.Println("Error saving password:", err)
			return
		}
		fmt.Println("Password saved successfully")
	},
}

var getCmd = &cobra.Command{
	Use:   "get [service] [username]",
	Short: "Get a password",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		service := args[0]
		username := args[1]

		pm, err := NewPasswordManager(masterPassword, "vault.file")
		if err != nil {
			fmt.Println("Error initializing password manager:", err)
			return
		}
		password, err := pm.GetPassword(service, username)
		if err != nil {
			fmt.Println("Error getting password:", err)
			return
		}
		fmt.Println("Password:", password)
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete [service] [username]",
	Short: "Delete a password",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		service := args[0]
		username := args[1]

		pm, err := NewPasswordManager(masterPassword, "vault.file")
		if err != nil {
			fmt.Println("Error initializing password manager:", err)
			return
		}
		err = pm.DeletePassword(service, username)
		if err != nil {
			fmt.Println("Error deleting password:", err)
			return
		}
		fmt.Println("Password deleted successfully")
	},
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new password vault",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print("Please type your master password: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println("Error reading password:", err)
			return
		}
		masterPassword = string(bytePassword)

		pm, err := NewPasswordManager(masterPassword, filePath)
		if err != nil {
			fmt.Println("Error initializing password manager:", err)
			return
		}
		err = pm.InitVault()
		if err != nil {
			fmt.Println("Error initializing vault:", err)
			return
		}
		fmt.Println("Vault initialized successfully")
	},
}

func init() {
	rootCmd.AddCommand(addCmd, getCmd, deleteCmd, initCmd)
	rootCmd.PersistentFlags().StringVar(&filePath, "file-path", "", "Path to the password vault file")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

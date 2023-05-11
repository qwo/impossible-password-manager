package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

var masterPassword string

var rootCmd = &cobra.Command{
	Use:   "mypasswordmanager",
	Short: "A simple password manager",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// TODO: Prompt the user for the master password
		masterPassword = "myMasterPassword"
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

		pm := NewPasswordManager(masterPassword)
		err := pm.SavePassword(service, username, password)
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

		fmt.Print("Please type your master password: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println("Error reading password:", err)
			return
		}
		masterPassword := string(bytePassword)

		pm := NewPasswordManager(masterPassword)
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

		pm := NewPasswordManager(masterPassword)
		err := pm.DeletePassword(service, username)
		if err != nil {
			fmt.Println("Error deleting password:", err)
			return
		}
		fmt.Println("Password deleted successfully")
	},
}

func init() {
	rootCmd.AddCommand(addCmd, getCmd, deleteCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

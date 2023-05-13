# impossible-password-manager
RC project May 11

## Introduction 

I want to build a password manager because I use them. I don't know whats under the hood so I think its good to build one to understand what passwords managers do so i can password manage password 

## impossible! 

- haven't written go since 2018 
- time constrained 1:30pm to ~5pm 
- write some docs and test 
- some presentation

## dependencies
go 1.9x


## Usage
```
Description
This is a simple command-line password manager written in Go. It allows you to securely store, retrieve, and delete passwords for various services. The passwords are encrypted using AES encryption and stored in a file on your local system. The password manager requires a master password to encrypt and decrypt the passwords.

Usage
Initialize the password vault:

You can initialize a new password vault using the init command. This will create an empty, encrypted file to store your passwords. You will be prompted to enter a master password, which will be used to encrypt and decrypt your passwords.

Description
This is a simple command-line password manager written in Go. It allows you to securely store, retrieve, and delete passwords for various services. The passwords are encrypted using AES encryption and stored in a file on your local system. The password manager requires a master password to encrypt and decrypt the passwords.

Usage
Initialize the password vault:

You can initialize a new password vault using the init command. This will create an empty, encrypted file to store your passwords. You will be prompted to enter a master password, which will be used to encrypt and decrypt your passwords.

bash
Copy code
./pm init
If you want to specify a different file path for the password vault, you can use the --file-path flag:

bash
Copy code
./pm init --file-path=/path/to/myvault
Add a password:

You can add a new password using the add command, followed by the service name, username, and password:

bash
Copy code
./pm add google.com myusername mypassword
The password will be encrypted and stored in the password vault.

Get a password:

You can retrieve a password using the get command, followed by the service name and username:

bash
Copy code
./pm get google.com myusername
You will be prompted to enter the master password. If the master password is correct, the password for the specified service and username will be decrypted and displayed.

Delete a password:

You can delete a password using the delete command, followed by the service name and username:

bash
Copy code
./pm delete google.com myusername
The password for the specified service and username will be removed from the password vault.

Notes
The master password is required to encrypt and decrypt the passwords in the vault. If you lose the master password, you will not be able to retrieve your passwords.
The password vault is a binary file and is not meant to be human-readable. If you want to view the contents of the vault, you must use the get command with the correct master password.
This is a simple implementation and does not include many features of a full-featured password manager, such as password generation, password change reminders, or syncing across devices. It is intended for educational purposes and not for storing real passwords.
```


-- get a design
-- pick the tools 
-- check and build your assumptions 
-- learned the syntax and the wrapping
    - dereferencing, passing reference
-- incremented and made bugs
-- future of programming 


sengming,patrick mccarver, sonke, bens, and ai buddy


AI


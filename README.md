# Password Encryption Tool

This is a simple Java-based GUI application that allows users to encrypt and decrypt passwords using AES, DES, and RSA encryption algorithms. It features a user-friendly graphical interface built with Java Swing and supports saving encrypted passwords to a text file for later use.

## Features

- **Multiple encryption algorithms**: Choose between AES (symmetric), DES (symmetric), and RSA (asymmetric).
- **Graphical User Interface**: Built using Java Swing.
- **File Saving**: Encrypted passwords are saved to a file (`encrypted_passwords.txt`) for future reference.
- **Password Decryption**: Decrypt previously encrypted passwords from the file or user input.

## Project Structure

- **Main Class**: `PasswordEncryptionApp.java` - The main class containing the encryption and decryption logic.
- **pom.xml**: Maven configuration file for building and running the project.
- **encrypted_passwords.txt**: File that stores encrypted passwords.

## How to Run the Application

### Prerequisites

- **Java 21 or higher**: Make sure you have JDK 21 installed.
- **Maven**: Ensure Maven is installed to build and run the project.

### Steps

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd <repository-directory>


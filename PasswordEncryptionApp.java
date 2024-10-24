/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package com.mycompany.encrpyt;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.awt.*;
import java.awt.event.*;
import java.util.Base64;
import java.io.*;
import javax.swing.*;

public class PasswordEncryptionApp extends JFrame implements ActionListener {

    private JTextField passwordInput;
    private JTextArea resultArea;
    private JComboBox<String> algorithmCombo;
    private SecretKey secretKey;
    private KeyPair rsaKeyPair;

    public PasswordEncryptionApp() {
        setTitle("Password Encryption Tool");
        setSize(500, 400);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new GridLayout(7, 1));
        getContentPane().setBackground(Color.LIGHT_GRAY);

        JLabel promptLabel = new JLabel("Enter Password:");
        promptLabel.setForeground(Color.BLUE);
        passwordInput = new JTextField();
        add(promptLabel);
        add(passwordInput);

        JLabel algorithmLabel = new JLabel("Select Encryption Algorithm:");
        algorithmLabel.setForeground(Color.BLUE);
        String[] algorithms = {"AES", "DES", "RSA"};
        algorithmCombo = new JComboBox<>(algorithms);
        add(algorithmLabel);
        add(algorithmCombo);

        JButton encryptButton = new JButton("Encrypt");
        encryptButton.setBackground(Color.GREEN);
        encryptButton.addActionListener(this);
        add(encryptButton);

        JButton decryptButton = new JButton("Decrypt");
        decryptButton.setBackground(Color.ORANGE);
        decryptButton.addActionListener(this);
        add(decryptButton);

        resultArea = new JTextArea();
        resultArea.setLineWrap(true);
        resultArea.setWrapStyleWord(true);
        add(new JScrollPane(resultArea));

        setVisible(true);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        String password = passwordInput.getText();
        String algorithm = (String) algorithmCombo.getSelectedItem();

        try {
            if (action.equals("Encrypt")) {
                switch (algorithm) {
                    case "AES":
                        secretKey = generateAESKey();
                        String encryptedAES = encryptAES(password, secretKey);
                        resultArea.setText("AES Encrypted: " + encryptedAES);
                        saveToFile(encryptedAES, algorithm);
                        break;
                    case "DES":
                        secretKey = generateDESKey();
                        String encryptedDES = encryptDES(password, secretKey);
                        resultArea.setText("DES Encrypted: " + encryptedDES);
                        saveToFile(encryptedDES, algorithm);
                        break;
                    case "RSA":
                        rsaKeyPair = generateRSAKeyPair();
                        String encryptedRSA = encryptRSA(password, rsaKeyPair.getPublic());
                        resultArea.setText("RSA Encrypted: " + encryptedRSA);
                        saveToFile(encryptedRSA, algorithm);
                        break;
                }
            } else if (action.equals("Decrypt")) {
                String encryptedText = JOptionPane.showInputDialog("Enter encrypted text:");
                if (encryptedText != null) {
                    switch (algorithm) {
                        case "AES":
                            if (secretKey != null) {
                                String decryptedAES = decryptAES(encryptedText, secretKey);
                                resultArea.setText("AES Decrypted: " + decryptedAES);
                            }
                            break;
                        case "DES":
                            if (secretKey != null) {
                                String decryptedDES = decryptDES(encryptedText, secretKey);
                                resultArea.setText("DES Decrypted: " + decryptedDES);
                            }
                            break;
                        case "RSA":
                            if (rsaKeyPair != null) {
                                String decryptedRSA = decryptRSA(encryptedText, rsaKeyPair.getPrivate());
                                resultArea.setText("RSA Decrypted: " + decryptedRSA);
                            }
                            break;
                    }
                }
            }
        } catch (Exception ex) {
            resultArea.setText("Error: " + ex.getMessage());
        }
    }

    private SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    private String encryptAES(String password, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String decryptAES(String encryptedText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    private SecretKey generateDESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        return keyGen.generateKey();
    }

    private String encryptDES(String password, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String decryptDES(String encryptedText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    private KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private String encryptRSA(String password, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String decryptRSA(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    private void saveToFile(String encryptedPassword, String algorithm) throws IOException {
        try (FileWriter writer = new FileWriter("encrypted_passwords.txt", true)) {
            writer.write("Algorithm: " + algorithm + " - Encrypted: " + encryptedPassword + "\n");
        }
    }

    public static void main(String[] args) {
        new PasswordEncryptionApp();
    }
}

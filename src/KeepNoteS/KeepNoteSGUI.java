/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* This code is free for use by anyone AS LONG AS YOU SHARE WHERE YOU GOT IT!
 * I also sincerely ask for credit where credit is due if you use this code
 * for anything useful. if you feel so inclined you may donate to my
 * coffee, snacks, and encouragement fund... it supplies caffine, chips,
 * and helps keep me coding. just open a browser and use this link:
 * https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=NZ5MHFDKKVFFN
 * ...and thank you! Have a wonderful day!
 */
package KeepNoteS;

import java.awt.Component;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

public class KeepNoteSGUI extends javax.swing.JFrame {
    final JFileChooser fc = new JFileChooser();
    
    private static final Random RANDOM = new SecureRandom();
    private static final String ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final String salt = "ThIsIsMySalt, WheRe is ThE Pepp3r? And I add Prime number 267199"; // This can be altered safely and is your salt
    private static int ITERATIONS = 1699; // prime number! This can be altered safely but must be a whole number
    private static int thePin = 0;
    private static final int KEY_LENGTH = 96;
    private static String encryptionKey = "bG3U7tr51alo7jHy"; // 16 chars generic to start with.... this does nothing as it's replaced!
    private static final String characterEncoding = "UTF-8";
    private static final String cipherTransformation = "AES/CBC/PKCS5PADDING";
    private static final String aesEncryptionAlgorithem = "AES";
    private static final String hashAlgo = "PBKDF2WithHmacSHA256";
    
    public KeepNoteSGUI() {
        initComponents();
    }

    private void saveFile() {
		File file;
                // Check validity, and process passphrase and pin to create key
                boolean test = checkPassAndPin();
                if (test == false) return;
		// create and display dialog box to get file name
		JFileChooser dialog = new JFileChooser();

		// Make sure the user didn't cancel the file chooser
		if (dialog.showSaveDialog(textArea) == JFileChooser.APPROVE_OPTION) {

			// Get the file the user selected
			file = dialog.getSelectedFile();

			try {
				// Now write to the file
				PrintWriter output = new PrintWriter(new FileWriter(file));
				output.print(encrypt(textArea.getText()));
                                output.close();
			} catch (IOException e) {
				JOptionPane.showMessageDialog(textArea, "Can't save file "
						+ e.getMessage());
			}
		}
                infoBox("File Saved!", "Saved");
	}
    
    private void loadFile() {
		String line;
		File file;
                // Check validity, and process passphrase and pin to create key
                boolean test = checkPassAndPin();
                if (test == false) return;               

		// create and display dialog box to get file name
		JFileChooser dialog = new JFileChooser();

		// Make sure the user did not cancel.
		if (dialog.showOpenDialog(textArea) == JFileChooser.APPROVE_OPTION) {
			// Find out which file the user selected.
			file = dialog.getSelectedFile();

			try {
				// Open the file.
				BufferedReader input = new BufferedReader(new FileReader(file));

				// Clear the editing area
				textArea.setText("");

				// read, decrypt, and post to view
				line = input.readLine();
				while (line != null) {
                                    textArea.append(decrypt(line/* + "\n"*/));
                                    line = input.readLine();
				}

				// Close the file
				input.close();
			} catch (IOException e) {
				JOptionPane.showMessageDialog(textArea, "Can't load file "
						+ e.getMessage());
			}
		}
	}
    
    public static String encrypt(String plainText) {
        String encryptedText = "";
        try {
            Cipher cipher = Cipher.getInstance(cipherTransformation);
            byte[] key = encryptionKey.getBytes(characterEncoding);
            SecretKeySpec secretKey = new SecretKeySpec(key, aesEncryptionAlgorithem);
            IvParameterSpec ivparameterspec = new IvParameterSpec(key);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivparameterspec);
            byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF8"));
            Base64.Encoder encoder = Base64.getEncoder();
            encryptedText = encoder.encodeToString(cipherText);

        } catch (Exception E) {
            System.err.println("Encrypt Exception : " + E.getMessage());
        }
        return encryptedText;
    }

    public static String decrypt(String encryptedText) {
        String decryptedText = "";
        try {
            Cipher cipher = Cipher.getInstance(cipherTransformation);
            byte[] key = encryptionKey.getBytes(characterEncoding);
            SecretKeySpec secretKey = new SecretKeySpec(key, aesEncryptionAlgorithem);
            IvParameterSpec ivparameterspec = new IvParameterSpec(key);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivparameterspec);
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] cipherText = decoder.decode(encryptedText.getBytes("UTF8"));
            decryptedText = new String(cipher.doFinal(cipherText), "UTF-8");

        } catch (Exception E) {
            //System.err.println("decrypt Exception : "+E.getMessage());
            decryptedText = "You may not have the correct key, unable to decipher!";
        }
        return decryptedText;
    }
    
    public static String getSalt(int length) {
        StringBuilder returnValue = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            returnValue.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return new String(returnValue);
    }

    public static byte[] hash(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        Arrays.fill(password, Character.MIN_VALUE);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(hashAlgo);
            return skf.generateSecret(spec).getEncoded();
        } 
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AssertionError("Error while hashing a password");
        } 
        finally {
            spec.clearPassword();
        }
    }

    public static void generateSecurePassword(String password) {
        ITERATIONS = thePin + (int)((float) (0.52289 * thePin)); //+ ITERATIONS;
        /*while (ITERATIONS > 40000) {
            ITERATIONS -= 1000; // 547 is a prime number!
        }*/
        String returnValue = null;
        byte[] securePassword = hash(password.toCharArray(), salt.getBytes());
        returnValue = Base64.getEncoder().encodeToString(securePassword);
        encryptionKey = returnValue;
    }
    
    private boolean checkPassAndPin() {
        // Check validity of both passphrase and PIN!
        if ("".equals(pass.getText())) {
            infoBox("Passphrase cannot be left blank while saving or loading a file! Please try again!", "WARNING!");
            return false;
        }
        try {
            thePin = Integer.parseInt(myPin.getText());
            if (thePin > 99999 || thePin < 1000) {
                infoBox("PIN must be between 1000 and 99999!", "Uh oh:");
                return false;
            }
        } 
        catch (NumberFormatException e) {
            infoBox("PIN cannot be left blank while saving or loading a file! Please try again!", "WARNING!");
            return false;
        }
                
        //Generate a key from the passphrase, the PIN is global and is picked up from generation()
        generateSecurePassword(pass.getText());
        return true;
    }
    
    public void infoBox(String infoMessage, String titleBar)
    {
        JOptionPane.showMessageDialog(null, infoMessage, titleBar, JOptionPane.INFORMATION_MESSAGE);
    }
    
    
    
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        pickFile = new javax.swing.JButton();
        pass = new javax.swing.JTextField();
        myPin = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        textArea = new javax.swing.JTextArea();
        newFile = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("KeepNoteS Version 1.0.1 - ©2018 B. Greg Colburn Jr.");

        pickFile.setText("Open File");
        pickFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pickFileActionPerformed(evt);
            }
        });

        jLabel1.setText("Passphrase:");

        jLabel2.setText("Pass Pin:");

        textArea.setColumns(20);
        textArea.setRows(5);
        jScrollPane1.setViewportView(textArea);

        newFile.setText("Save Contents");
        newFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                newFileActionPerformed(evt);
            }
        });

        jLabel3.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel3.setText("Keep Keys is written by B. Greg Colburn Jr - (c)2018 and is Freeware - Source Code Available at github");

        jButton1.setText("Website");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jButton2.setText("Github");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(pickFile, javax.swing.GroupLayout.PREFERRED_SIZE, 91, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(newFile, javax.swing.GroupLayout.PREFERRED_SIZE, 120, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(pass, javax.swing.GroupLayout.PREFERRED_SIZE, 383, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(myPin))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 658, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 87, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jScrollPane1))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(pickFile)
                    .addComponent(newFile)
                    .addComponent(pass, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1)
                    .addComponent(myPin, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 351, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(jButton1)
                    .addComponent(jButton2))
                .addContainerGap(17, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void pickFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pickFileActionPerformed
        loadFile();
    }//GEN-LAST:event_pickFileActionPerformed

    private void newFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newFileActionPerformed
        saveFile();
    }//GEN-LAST:event_newFileActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        String moreInfo = "https://gregneedsajob.com";
        try {
            java.awt.Desktop.getDesktop().browse(java.net.URI.create(moreInfo));
        } catch (java.io.IOException e) {
            System.out.println(e.getMessage());
        }
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        String moreInfo = "https://github.com/thepony";
        try {
            java.awt.Desktop.getDesktop().browse(java.net.URI.create(moreInfo));
        } catch (java.io.IOException e) {
            System.out.println(e.getMessage());
        }
    }//GEN-LAST:event_jButton2ActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(KeepNoteSGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(KeepNoteSGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(KeepNoteSGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(KeepNoteSGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new KeepNoteSGUI().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextField myPin;
    private javax.swing.JButton newFile;
    private javax.swing.JTextField pass;
    private javax.swing.JButton pickFile;
    private javax.swing.JTextArea textArea;
    // End of variables declaration//GEN-END:variables
}

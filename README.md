# AES Cipher

## About the project
This project is a python implementation of 4 modes(ECB, CBC, CTR, CCM) of the AES cipher from scratch. The user interface is built using tkinter.
## Purpose of the project
The purpose of this project was to learn and understand how AES works. It is not meant for commercial use.
## How to use
### Selecting the mode and opening the file
In the first tab of the app, select the mode you wish to encrypt your file with. You can open the file you wish to encrypt using the `open file` button.
### Keys
In the `keys` tab, you can save the key currently used in the app, or you can load a previously saved key.
### IVs
In the `IVs` tab, you can load a previously saved IV, which is saved when encrypting the file with CBC, CTR and CCM modes.
### Encryption/Decryption
In the `encryption` tab, you can encrypt or decrypt the selected file with the selected mode.
## About AES
Advanced Encryption Standard (AES) is a specification for the encryption of electronic data established by the U.S National Institute of Standards and Technology (NIST) in 2001. AES is widely used today as it is a much stronger than DES and triple DES despite being harder to implement.

Points to remember
 - AES is a block cipher.
 - The key size can be 128/192/256 bits.
 - Encrypts data in blocks of 128 bits each.

That means it takes 128 bits as input and outputs 128 bits of encrypted cipher text as output. AES relies on substitution-permutation network principle which means it is performed using a series of linked operations which involves replacing and shuffling of the input data.
[More about AES](https://www.geeksforgeeks.org/advanced-encryption-standard-aes/)
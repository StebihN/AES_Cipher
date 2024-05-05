![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

# AES Cipher
A python implementation of 4 modes(ECB, CBC, CTR, CCM) of the AES cipher from scratch. The user interface allows the user to select one of the 4 modes and encrypt or decrypt the selected file with it. Encryption key and IV can also be saved for later decryption.

The UI was built using tkinter.

### About AES
Advanced Encryption Standard (AES) is a specification for the encryption of electronic data established by the U.S National Institute of Standards and Technology (NIST) in 2001. AES is widely used today as it is a much stronger than DES and triple DES despite being harder to implement.

Points to remember
 - AES is a block cipher.
 - The key size can be 128/192/256 bits.
 - Encrypts data in blocks of 128 bits each.

That means it takes 128 bits as input and outputs 128 bits of encrypted cipher text as output. AES relies on substitution-permutation network principle which means it is performed using a series of linked operations which involves replacing and shuffling of the input data.
More about AES [here](https://www.geeksforgeeks.org/advanced-encryption-standard-aes/).
## Motivation For The Project
The project was created to learn and understand how AES works. It is not meant for commercial use.
## How To Use

1. **Selecting the mode and opening the file:** Select the mode you wish to encrypt your file with in the `Home` tab of the app. Open the file you wish to encrypt using the `Open file` button.

![Home Page](https://github.com/StebihN/AES_Cipher/assets/121977112/9bb855ea-1210-4be0-8d7c-d115b7f0a65c)

2. **Saving/loading the encryption key:** In the `Keys` tab, the user can save the key currently used in the app by clicking the `Save key` button, or load a previously saved key with the `Load key` button.

![Keys Page](https://github.com/StebihN/AES_Cipher/assets/121977112/e0bf1188-ab97-4610-bf8d-d14cdc0d67eb)

3. **Loading the IV:** In the `IVs` tab, the user can load a previously saved IV, which is saved when encrypting the file with CBC, CTR and CCM modes. This is done by clicking the `Load IV` button.

![IVs Page](https://github.com/StebihN/AES_Cipher/assets/121977112/33271b63-ca0f-456d-8a1d-d97d3a007141)

4. **Encryption/Decryption:** In the `Encryption` tab, the user can encrypt or decrypt the selected file with the selected mode. **NOTE:** when encrypting the file with CBC, CTR and CCM modes, the user will first be asked to save the IV and then the file. To decrypt with the mentioned modes, the user needs to first load the saved IV.

![Encryption Page](https://github.com/StebihN/AES_Cipher/assets/121977112/e37c790d-147d-474c-81a0-54b6cd766394)


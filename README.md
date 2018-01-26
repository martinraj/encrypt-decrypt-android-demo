# Encrypt/Decrypt Demo
In this demo, the text entered in the edittext is encrypted using the app instance and the encrypted text is shown. On clicking decrypt button the encrypted text is decrypted and real text is shown.
## Instructions
In EncUtil class, You have to generate randomized FIXED_IV and change the KEY_ALIAS using your own values. FIXED_IV is used to randomize the encrypted text. Here I have used the final value of fixed IV(fixed four) as "randomizemsg", which is ok for demo purpose. Generate this randomly for every time you encrypt a text for using it in production.
KEY_ALIAS is the name of place where the generated key for our app will be stored inside key store in the specifed name.

For Android Versions less than KITKAT, I have used RSA certificate to encrypt and decrypt the data.

## Screenshots
### Main Page
![Main_page](https://github.com/martinraj/encrypt-decrypt-android-demo/blob/master/screenshots/main_page.png)
### After Encrypt
![after_encrypt](https://github.com/martinraj/encrypt-decrypt-android-demo/blob/master/screenshots/after_encrypt.png)
### After Decrypt
![after_decrypt](https://github.com/martinraj/encrypt-decrypt-android-demo/blob/master/screenshots/after_decrypt.png)

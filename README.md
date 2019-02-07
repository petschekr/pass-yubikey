## `pass-yubikey`
### A self-contained way to interact with and read from the encrypted [`pass`](https://www.passwordstore.org/) password store.

Comprises two parts:
- A library for performing PGP cryptographic operations on YubiKey devices and parsing and decrypting encrypted PGP files _(unstable API at the moment)_
- A binary application that uses the library to find the correct password file to read, unlocks the YubiKey, decrypts the password and associated content, and copies the password to the system's clipboard. Also supports generating TOTP codes if the password line is in the TOTP URL format.

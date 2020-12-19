# Crypto-exporting-a-Session-Key

The following example creates a random session key and creates an exportable key BLOB. The example illustrates the use of CryptGetUserKey, CryptExportKey, and related functions.

This example illustrates the following tasks and CryptoAPI functions:

- Acquiring a CSP context using CryptAcquireContext.
- Gaining access to two different pairs of public/private keys using CryptGetUserKey.
- Generating an exportable session key using CryptGenKey.
- Creating a simple key BLOB containing a session key using CryptExportKey.
- Destroying a session key and access to the two pairs of public/private keys using CryptDestroyKey.
 -Releasing the CSP context using CryptReleaseContext.

This example uses the function MyHandleError. The code for this function is included with the sample. Code for this and other auxiliary functions is also listed under General Purpose Functions.

Source : https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-exporting-a-session-key

// Crypto.cpp : Este archivo contiene la función "main". 
// La ejecución del programa comienza y termina ahí.

//--------------------------------------------------------------------

// Copyright (C) Microsoft.  
// All rights reserved.
// This example program creates a session key and a simple key 
// BLOB holding that session key. The key BLOB can be written to disk 
// and later read from a disk file.

#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <iostream>
using namespace std;

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

void MyHandleError(const char *s);

void main(void) {

	std::cout << "Hello World!\n";

	//--------------------------------------------------------------------
	// Declare and initialize variables.

	HCRYPTPROV hProv;       // CSP handle
	HCRYPTKEY hSignKey;     // Signature key pair handle
	HCRYPTKEY hXchgKey;     // Exchange key pair handle
	HCRYPTKEY hKey;         // Session key handle
	BYTE *pbKeyBlob;        // Pointer to a simple key BLOB
	DWORD dwBlobLen;        // The length of the key BLOB

	//--------------------------------------------------------------------
	//https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta
	// Acquire a cryptographic provider context handle.
	if (CryptAcquireContext(&hProv,NULL,NULL,PROV_RSA_FULL,0))
		printf("The CSP has been acquired. \n");
	else
		MyHandleError("Error during CryptAcquireContext.");

	//--------------------------------------------------------------------
	//https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgetuserkey
	// Get a handle to the signature key.
	// The signature key must exist before it can be retrieved. For more
	// information, see the CryptGetUserKey documentation.

	if (CryptGetUserKey(hProv,AT_SIGNATURE,&hSignKey))
		printf("The signature key has been acquired. \n");
	else
		MyHandleError("Error during CryptGetUserKey for signkey.");

	//--------------------------------------------------------------------
	//https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgetuserkey
	// Get a handle to the key exchange key.
	// The key must exist before it can be retrieved. For more
	// information, see the CryptGetUserKey documentation.

	if (CryptGetUserKey(hProv,AT_KEYEXCHANGE,&hXchgKey))
		printf("The key exchange key has been acquired. \n");
	else
		printf("Error during CryptGetUserKey exchange key.");
	
	// hSignKey may be used to verify a signature. hXchgKey will be used to export a session key.

	//--------------------------------------------------------------------
	//https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenkey
	// Generate a session key.

	if (CryptGenKey(hProv,CALG_RC4,CRYPT_EXPORTABLE,&hKey))
		printf("Original session key is created. \n");
	else
		MyHandleError("ERROR -- CryptGenKey.");

	// Determine the size of the key BLOB and allocate memory.
	//https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptexportkey

	if (CryptExportKey(hKey,hXchgKey,SIMPLEBLOB,0,NULL,&dwBlobLen))
		printf("Size of the BLOB for the session key determined. \n");
	else
		MyHandleError("Error computing BLOB length.");

	if (pbKeyBlob = (BYTE*)malloc(dwBlobLen))
		printf("Memory has been allocated for the BLOB. \n");
	else
		MyHandleError("Out of memory. \n");

	//--------------------------------------------------------------------
	// 
	// Export the key into a simple key BLOB.

	if (CryptExportKey(hKey,hXchgKey,SIMPLEBLOB,0,pbKeyBlob,&dwBlobLen))
		printf("Contents have been written to the BLOB. \n");
	else
		MyHandleError("Error during CryptExportKey.");

	//--------------------------------------------------------------------
	//   At this point, other processing such as writing the key BLOB to
	//   a file could be done.

	//--------------------------------------------------------------------
	// After all processing, clean up.

	//--------------------------------------------------------------------
	//  Free the memory used by the key BLOB.

	free(pbKeyBlob);

	// Destroy the session key.
	if (hKey)
		CryptDestroyKey(hKey);

	// Destroy the signature key handle.
	if (hSignKey)
		CryptDestroyKey(hSignKey);

	// Destroy the key exchange key handle.
	if (hXchgKey)
		CryptDestroyKey(hXchgKey);

	// Release the provider handle.
	if (hProv)
		CryptReleaseContext(hProv, 0);

	printf("The program ran to completion without error. \n");

}// End of main                                                    

//--------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message and exit 
//  the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void MyHandleError(const char* s)
{
	printf("An error occurred in running the program.\n");
	printf("%s\n", s);
	printf("Error number %x\n.", GetLastError());
	printf("Program terminating.\n");
	exit(1);
}
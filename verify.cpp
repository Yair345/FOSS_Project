#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <wincrypt.h>
#include <WinTrust.h>
#include <SoftPub.h>
#include <imagehlp.h>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Imagehlp.lib")


typedef BOOL(WINAPI* PFN_CRYPT_VERIFY_DETACHED_MESSAGE_SIGNATURE)(
    DWORD dwFlags,
    PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
    DWORD dwSignerIndex,
    const BYTE* pbDetachedSignBlob,
    DWORD cbDetachedSignBlob,
    const BYTE* pbToBeSignedBlob,
    DWORD cbToBeSignedBlob,
    PCCERT_CONTEXT* ppSignerCert
    );

bool IsDllSignatureVerified(HMODULE hModule) {
    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    // Get the NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    // Find the security directory
    DWORD secDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    DWORD secDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

    if (secDirRva == 0 || secDirSize == 0) {
        return false; // No security directory
    }

    // Get the certificate data
    LPWIN_CERTIFICATE winCert = (LPWIN_CERTIFICATE)((BYTE*)hModule + secDirRva);

    // Load the Crypt32.dll dynamically
    HMODULE hCrypt32 = LoadLibraryW(L"Crypt32.dll");
    if (hCrypt32 == NULL) {
        return false;
    }

    PFN_CRYPT_VERIFY_DETACHED_MESSAGE_SIGNATURE pCryptVerifyDetachedMessageSignature =
        (PFN_CRYPT_VERIFY_DETACHED_MESSAGE_SIGNATURE)GetProcAddress(hCrypt32, "CryptVerifyDetachedMessageSignature");

    if (pCryptVerifyDetachedMessageSignature == NULL) {
        FreeLibrary(hCrypt32);
        return false;
    }

    // Set up verification parameters
    CRYPT_VERIFY_MESSAGE_PARA verifyPara = { 0 };
    verifyPara.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    verifyPara.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    // Extract the actual signature from the WIN_CERTIFICATE structure
    DWORD signatureOffset = sizeof(DWORD) + sizeof(WORD) + sizeof(WORD); // dwLength + wRevision + wCertificateType
    const BYTE* signature = winCert->bCertificate + signatureOffset;
    DWORD signatureSize = winCert->dwLength - signatureOffset;

    // The data to be signed is everything up to the security directory
    const BYTE* dataToSign = (const BYTE*)hModule;
    DWORD dataToSignSize = secDirRva;

    // Verify the signature
    PCCERT_CONTEXT pSignerCert = NULL;
    BOOL result = FALSE;

        result = pCryptVerifyDetachedMessageSignature(
            0,  // dwFlags
            &verifyPara,
            0,  // dwSignerIndex
            signature,
            signatureSize,
            dataToSign,
            dataToSignSize,
            &pSignerCert
        );


        result = FALSE;

    // Clean up
    if (pSignerCert) {
        CertFreeCertificateContext(pSignerCert);
    }
    FreeLibrary(hCrypt32);

    return result != FALSE;
}


// Function to load the DLL and return the HMODULE handle
HMODULE LoadMyDLL()
{
    // Path to the DLL on the desktop
    const char* dllPath = "C:\\FOSS\\mydll.dll";

    // Load the DLL
    HMODULE hModule = LoadLibraryA(dllPath);

    // Check if the DLL was loaded successfully
    if (hModule == NULL)
    {
        std::cerr << "Failed to load DLL. Error: " << GetLastError() << std::endl;
    }
    else
    {
        std::cout << "DLL loaded successfully." << std::endl;
    }

    // Return the handle to the DLL
    return hModule;
}

int main() {
    // Load the DLL and get the handle
    HMODULE hModule = LoadMyDLL();

    bool isVerified = IsDllSignatureVerified(hModule);
    // If needed, you can now use the hModule to get function pointers from the DLL
    if (isVerified) {
        std::cout << "DLL signature is verified." << std::endl;
    }
    else {
        std::cout << "DLL signature is not verified." << std::endl;
    }
    // When done with the DLL, free it
    if (hModule != NULL)
    {
        FreeLibrary(hModule);
        std::cout << "DLL unloaded successfully." << std::endl;
    }
}

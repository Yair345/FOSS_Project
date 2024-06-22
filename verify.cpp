
#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <dbghelp.h>
#include <stdexcept>
#include <wintrust.h>
#include <DbgHelp.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "dbghelp.lib")


bool verify(HMODULE hModule, const std::wstring& caName) {
    bool isVerified = false;
    LPVOID lpData = nullptr;
    SIZE_T dwSize = 0;

    try {
        // Get the base address of the module
        lpData = (LPVOID)hModule;

        // Get information about the module's memory region
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(lpData, &mbi, sizeof(mbi)) == 0) {
            throw std::runtime_error("Failed to query module information");
        }

        // The size of the module is the size of its memory region
        dwSize = mbi.RegionSize;

        // Find the certificate in the module's resources
        DWORD certSize = 0;
        LPVOID certData = nullptr;
        PIMAGE_NT_HEADERS ntHeaders = ImageNtHeader(lpData);
        if (ntHeaders) {
            DWORD certDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
            certSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            if (certDirRva != 0 && certSize != 0) {
                certData = static_cast<BYTE*>(lpData) + certDirRva;
            }
        }

        if (certData == nullptr || certSize == 0) {
            throw std::runtime_error("No certificate found in the module");
        }

        // Parse the WIN_CERTIFICATE structure
        LPWIN_CERTIFICATE winCert = static_cast<LPWIN_CERTIFICATE>(certData);

        // Open the system ROOT store
        HCERTSTORE hRootStore = CertOpenSystemStore(NULL, L"ROOT");
        if (!hRootStore) {
            throw std::runtime_error("Failed to open ROOT certificate store");
        }

        // Create a message to verify
        HCRYPTMSG hMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
        if (!hMsg) {
            CertCloseStore(hRootStore, 0);
            throw std::runtime_error("Failed to open message for decoding");
        }

        // Update the message with the certificate data
        if (!CryptMsgUpdate(hMsg, winCert->bCertificate, winCert->dwLength, TRUE)) {
            CryptMsgClose(hMsg);
            CertCloseStore(hRootStore, 0);
            throw std::runtime_error("Failed to update message with certificate data");
        }

        // Get signer information
        DWORD signerInfoSize = 0;
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize)) {
            CryptMsgClose(hMsg);
            CertCloseStore(hRootStore, 0);
            throw std::runtime_error("Failed to get signer info size");
        }

        std::vector<BYTE> signerInfo(signerInfoSize);
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfo.data(), &signerInfoSize)) {
            CryptMsgClose(hMsg);
            CertCloseStore(hRootStore, 0);
            throw std::runtime_error("Failed to get signer info");
        }

        PCMSG_SIGNER_INFO pSignerInfo = (PCMSG_SIGNER_INFO)signerInfo.data();

        // Find the signer certificate in the store
        CERT_INFO certInfo;
        certInfo.Issuer = pSignerInfo->Issuer;
        certInfo.SerialNumber = pSignerInfo->SerialNumber;

        PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hRootStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &certInfo, NULL);

        if (!pCertContext) {
            CryptMsgClose(hMsg);
            CertCloseStore(hRootStore, 0);
            throw std::runtime_error("Signer certificate not found in ROOT store");
        }

        // Verify the certificate chain
        CERT_CHAIN_PARA chainPara = { sizeof(CERT_CHAIN_PARA) };
        PCCERT_CHAIN_CONTEXT pChainContext = nullptr;

        if (!CertGetCertificateChain(NULL, pCertContext, NULL, hRootStore, &chainPara, 0, NULL, &pChainContext)) {
            CertFreeCertificateContext(pCertContext);
            CryptMsgClose(hMsg);
            CertCloseStore(hRootStore, 0);
            throw std::runtime_error("Failed to get certificate chain");
        }

        // Check if the certificate is issued by the specified CA
        for (DWORD i = 0; i < pChainContext->cChain; i++) {
            for (DWORD j = 0; j < pChainContext->rgpChain[i]->cElement; j++) {
                CERT_INFO* certInfo = pChainContext->rgpChain[i]->rgpElement[j]->pCertContext->pCertInfo;
                DWORD nameSize = CertGetNameStringW(pChainContext->rgpChain[i]->rgpElement[j]->pCertContext,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
                std::vector<wchar_t> nameBuffer(nameSize);
                CertGetNameStringW(pChainContext->rgpChain[i]->rgpElement[j]->pCertContext,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, nameBuffer.data(), nameSize);

                if (caName == std::wstring(nameBuffer.data())) {
                    isVerified = true;
                    break;
                }
            }
            if (isVerified) break;
        }

        // Clean up
        CertFreeCertificateChain(pChainContext);
        CertFreeCertificateContext(pCertContext);
        CryptMsgClose(hMsg);
        CertCloseStore(hRootStore, 0);

    }
    catch (const std::exception& e) {
        // Handle any exceptions (you might want to log this)
        OutputDebugStringA(e.what());
    }

    return isVerified;
}
int main() {
    // Load kernel32.dll
    HMODULE hModule = GetModuleHandle(L"kernel32.dll");
    if (hModule == NULL) {
        std::cerr << "Failed to get handle to kernel32.dll" << std::endl;
        return 1;
    }

    // The CA name for Microsoft Windows
    std::wstring caName = L"Microsoft Windows";

    // Verify the DLL
    bool isVerified = verify(hModule, caName);

    if (isVerified) {
        std::cout << "kernel32.dll is verified and signed by Microsoft Windows." << std::endl;
    }
    else {
        std::cout << "kernel32.dll verification failed or it's not signed by Microsoft Windows." << std::endl;
    }

    return 0;
}
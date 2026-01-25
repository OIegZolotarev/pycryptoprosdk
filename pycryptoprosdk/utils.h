#pragma once

#include <string>
#include <optional>
#include <wincrypt.h>

#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

// ================= Данные сертификата

typedef struct certificateData_s 
{
	HCERTSTORE hStoreHandle = NULL;
	PCCERT_CONTEXT pCertContext = NULL;

	ALG_ID getAlgId();

	CERT_PUBLIC_KEY_INFO* PublicKeyInfo()
	{
		return &pCertContext->pCertInfo->SubjectPublicKeyInfo;
	}

}certificateData_t;


typedef std::optional<certificateData_t> optCertificateData_t;

optCertificateData_t GetCertificateData(const char* storeName, const char* thumbPrint);
void ReleaseCertificateData(optCertificateData_t & data);


// Контекст ключа

typedef struct privateKeyContext_s 
{
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
	DWORD							dwKeySpec = 0;
	BOOL							bFreeKey = FALSE;
	BOOL							bIsCNG = FALSE;
}privateKeyContext_t;

typedef std::optional<privateKeyContext_t> optPrivateKeyContext_t;

optPrivateKeyContext_t GetPrivateKeyContext(optCertificateData_t & certData);
void ReleasePrivateKeyContext(optPrivateKeyContext_t& context);


// Source - https://stackoverflow.com/a
// Posted by Naszta, modified by community. See post 'Timeline' for change history
// Retrieved 2026-01-25, License - CC BY-SA 3.0

#include <Wincrypt.h>

enum HashType
{
	HashSha1, HashMd5, HashSha256
};

std::string GetHashText(const void* data, const size_t data_size, HashType hashType);

void DebugData(const char* tag, const void* data, const size_t len);

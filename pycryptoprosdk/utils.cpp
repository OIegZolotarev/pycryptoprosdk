#include <Python.h>
#include <windows.h>
#include <Wincrypt.h>
#include <WinCryptEx.h>
#include <vector>
#include <sstream>

#include "strings_helper.h"

#include "utils.h"

extern PyObject* CertDoesNotExist;

optCertificateData_t GetCertificateData(const char * _storeName, const char* _thumbprint)
{
	wchar_t* storeName = stringConverter.convertFromUTF8(_storeName);
	wchar_t* thumbprint = stringConverter.convertFromUTF8(_thumbprint);

	HCERTSTORE hStoreHandle;
	PCCERT_CONTEXT pCertContext = NULL;

	BYTE pDest[64];
	DWORD nOutLen = sizeof(pDest);

	if (!CryptStringToBinaryW(thumbprint, (DWORD)wcslen(thumbprint), CRYPT_STRING_HEX, pDest, &nOutLen, 0, 0)) {
		PyErr_SetString(PyExc_Exception, "CryptStringToBinaryW failed.");
		return std::nullopt;
	}

	CRYPT_HASH_BLOB para;
	para.pbData = pDest;
	para.cbData = nOutLen;

	hStoreHandle = CertOpenSystemStoreW(0, storeName);
	pCertContext = CertFindCertificateInStore(hStoreHandle, MY_ENCODING_TYPE, 0, CERT_FIND_HASH, &para, NULL);

	if (!pCertContext) {
		CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
		PyErr_SetString(CertDoesNotExist, "Could not find the desired certificate.");
		return std::nullopt;
	}


	certificateData_t d;
	d.hStoreHandle = hStoreHandle;
	d.pCertContext = pCertContext;

	return std::optional<certificateData_t>(d);
}

void ReleaseCertificateData(optCertificateData_t &  data)
{
	if (!data.has_value())
		return;

	if (data->pCertContext) CertFreeCertificateContext(data->pCertContext);
	if (data->hStoreHandle) CertCloseStore(data->hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
}

optPrivateKeyContext_t GetPrivateKeyContext(optCertificateData_t& certData)
{
	privateKeyContext_t cont;

	if (!CryptAcquireCertificatePrivateKey(
		certData->pCertContext,
		CRYPT_ACQUIRE_SILENT_FLAG,
		NULL,
		&cont.hKey,
		&cont.dwKeySpec,
		&cont.bFreeKey
	)) {
		PyErr_Format(PyExc_ValueError,	"CryptAcquireCertificatePrivateKey failed (0x%x)", GetLastError());
		return std::nullopt;
	}

	cont.bIsCNG = (cont.dwKeySpec == CERT_NCRYPT_KEY_SPEC);

	return optPrivateKeyContext_t(cont);	
}

void ReleasePrivateKeyContext(optPrivateKeyContext_t& context)
{
	if (!context.has_value())
		return;

	if (context->bIsCNG) 
		NCryptFreeObject((NCRYPT_KEY_HANDLE)context->hKey);
	else
		CryptReleaseContext(context->hKey, 0);


}

std::string GetHashText(const void* data, const size_t data_size, HashType hashType)
{
	HCRYPTPROV hProv = NULL;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return "";
	}

	BOOL hash_ok = FALSE;
	HCRYPTPROV hHash = NULL;
	switch (hashType) {
	case HashSha1: hash_ok = CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash); break;
	case HashMd5: hash_ok = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash); break;
	case HashSha256: hash_ok = CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash); break;
	}

	if (!hash_ok) {
		CryptReleaseContext(hProv, 0);
		return "";
	}

	if (!CryptHashData(hHash, static_cast<const BYTE*>(data), data_size, 0)) {
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return "";
	}

	DWORD cbHashSize = 0, dwCount = sizeof(DWORD);
	if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHashSize, &dwCount, 0)) {
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return "";
	}

	std::vector<BYTE> buffer(cbHashSize);
	if (!CryptGetHashParam(hHash, HP_HASHVAL, reinterpret_cast<BYTE*>(&buffer[0]), &cbHashSize, 0)) {
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return "";
	}

	std::ostringstream oss;

	for (std::vector<BYTE>::const_iterator iter = buffer.begin(); iter != buffer.end(); ++iter) {
		oss.fill('0');
		oss.width(2);
		oss << std::hex << static_cast<const int>(*iter);
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	return oss.str();
}

void DebugData(const char* tag, const void* data, const size_t len)
{
	auto h = GetHashText(data, len, HashMd5);
	printf("[Data debugger]%s = %s\n", tag, h.c_str());
}

ALG_ID certificateData_s::getAlgId()
{
	const char* oid =
		pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;

	if (strcmp(oid, szOID_CP_GOST_R3410EL) == 0)
		return CALG_GR3411;
	else if (strcmp(oid, szOID_CP_GOST_R3410_12_256) == 0)
		return CALG_GR3411_2012_256;
	else if (strcmp(oid, szOID_CP_GOST_R3410_12_512) == 0)
		return CALG_GR3411_2012_512;
}



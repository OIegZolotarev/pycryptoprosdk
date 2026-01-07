#define PY_SSIZE_T_CLEAN

#include <stdio.h>
#include <io.h>
#include <fcntl.h>

#include <Python.h>
#include <datetime.h>

#include <string.h>
#include <string>
#include <WinCryptEx.h>
#include <cades.h>

#include <vector>

#include <windows.h> // Required for MultiByteToWideChar
#include <iostream>  // For console output


#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "amd64/cades.lib")


#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define CERT_NAME_STR_TYPE (CERT_X500_NAME_STR | CERT_NAME_STR_CRLF_FLAG)

#include "strings_helper.h"

static PyObject* CertDoesNotExist = NULL;

// start helpers -------------------------------------------------------------------------------------------------------

ALG_ID GetAlgId(const char* algString) {
	if (!algString) {
		return 0;
	}

	std::string str(algString);

	if ("CALG_GR3411" == str)
		return CALG_GR3411;

	if ("CALG_GR3411_2012_256" == str)
		return CALG_GR3411_2012_256;

	if ("CALG_GR3411_2012_512" == str)
		return CALG_GR3411_2012_512;

	return 0;
}

char * GetHashOidByKeyOid(IN char *szKeyOid) {

    if (strcmp(szKeyOid, szOID_CP_GOST_R3410EL) == 0) {
	    return szOID_CP_GOST_R3411;
    }
    else if (strcmp(szKeyOid, szOID_CP_GOST_R3410_12_256) == 0) {
	    return szOID_CP_GOST_R3411_12_256;
    }
    else if (strcmp(szKeyOid, szOID_CP_GOST_R3410_12_512) == 0) {
	    return szOID_CP_GOST_R3411_12_512;
    }

    return NULL;
}

PyObject * FileTimeToPyDateTime(FILETIME *fileTime) {
    PyDateTime_IMPORT;
    SYSTEMTIME systemTime;
    FileTimeToSystemTime(fileTime, &systemTime);

    return PyDateTime_FromDateAndTime(
        systemTime.wYear,
        systemTime.wMonth,
        systemTime.wDay,
        systemTime.wHour,
        systemTime.wMinute,
        systemTime.wSecond,
        0
    );
}

PyObject* GetCertName(CERT_NAME_BLOB name) {
	DWORD cbSize = CertNameToStrW(MY_ENCODING_TYPE, &name, CERT_NAME_STR_TYPE, NULL, 0);
	std::vector<wchar_t> subject(cbSize);

	CertNameToStrW(MY_ENCODING_TYPE, &name, CERT_NAME_STR_TYPE, subject.data(), cbSize);

	return PyUnicode_FromWideChar(subject.data(), cbSize - 1);
}


PyObject* GetThumbprint(PCCERT_CONTEXT pCertContext) {
	DWORD dataSize;
	CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, NULL, &dataSize);

	std::vector<BYTE> hash(dataSize);
	CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, hash.data(), &dataSize);

	DWORD hashStringSize;
	CryptBinaryToStringW(hash.data(), dataSize, CRYPT_STRING_HEX, NULL, &hashStringSize);

	std::vector<wchar_t> thumbprint(hashStringSize);
	CryptBinaryToStringW(hash.data(), dataSize, CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF, thumbprint.data(), &hashStringSize);

	return PyUnicode_FromWideChar(thumbprint.data(), hashStringSize);
}

PyObject * GetCertAltName(PCCERT_CONTEXT pCertContext) {
    PCERT_EXTENSION pExtension;

    pExtension = CertFindExtension(
        szOID_SUBJECT_ALT_NAME2,
        pCertContext->pCertInfo->cExtension,
        pCertContext->pCertInfo->rgExtension
    );

    if (pExtension) {
        LPVOID pvStructInfo;
        CERT_ALT_NAME_INFO *pAltNameInfo;
        DWORD cbStructInfo;
        CERT_NAME_BLOB directoryName;

        CryptDecodeObject(
            X509_ASN_ENCODING,
            szOID_SUBJECT_ALT_NAME2,
            pExtension->Value.pbData,
            pExtension->Value.cbData,
            0,
            0,
            &cbStructInfo
        );

        pvStructInfo = LocalAlloc(LMEM_FIXED, cbStructInfo);

        CryptDecodeObject(
            X509_ASN_ENCODING,
            szOID_SUBJECT_ALT_NAME2,
            pExtension->Value.pbData,
            pExtension->Value.cbData,
            0,
            pvStructInfo,
            &cbStructInfo
        );

        pAltNameInfo = (CERT_ALT_NAME_INFO *)pvStructInfo;

        for (DWORD i = 0;  i < pAltNameInfo->cAltEntry; i++) {
            const CERT_ALT_NAME_ENTRY& entry = pAltNameInfo->rgAltEntry[i];

            if (entry.dwAltNameChoice == CERT_ALT_NAME_DIRECTORY_NAME) {
                directoryName = entry.DirectoryName;

                DWORD cbSize = CertNameToStr(X509_ASN_ENCODING, &directoryName, CERT_NAME_STR_TYPE, NULL, 0);

                std::vector<char> certAltName(cbSize);
                CertNameToStr(X509_ASN_ENCODING, &directoryName, CERT_NAME_STR_TYPE, certAltName.data(), cbSize);

                LocalFree(pvStructInfo);

                return PyUnicode_FromString(certAltName.data());
            }
        }

        LocalFree(pvStructInfo);
    }

    return Py_None;
}

PyObject * GetCertInfo(PCCERT_CONTEXT pCertContext) {
    PyObject * certInfo = PyDict_New();

    PyDict_SetItemString(certInfo, "subject", GetCertName(pCertContext->pCertInfo->Subject));
    PyDict_SetItemString(certInfo, "issuer", GetCertName(pCertContext->pCertInfo->Issuer));
    PyDict_SetItemString(certInfo, "notValidBefore", FileTimeToPyDateTime(&pCertContext->pCertInfo->NotBefore));
    PyDict_SetItemString(certInfo, "notValidAfter", FileTimeToPyDateTime(&pCertContext->pCertInfo->NotAfter));
    PyDict_SetItemString(certInfo, "thumbprint", GetThumbprint(pCertContext));
    PyDict_SetItemString(certInfo, "altName", GetCertAltName(pCertContext));


    PyObject* der_data = PyBytes_FromStringAndSize(
        (const char*)pCertContext->pbCertEncoded,
        pCertContext->cbCertEncoded
    );
    PyDict_SetItemString(certInfo, "der_data", der_data);
    Py_DECREF(der_data);  // PyDict_SetItemString увеличивает refcount

    return certInfo;
}

// end helpers ---------------------------------------------------------------------------------------------------------

static PyObject* CreateHash(PyObject* self, PyObject* args) {
	const char* message;
	Py_ssize_t length;
	char* algString = nullptr;

	if (!PyArg_ParseTuple(args, "y#s", &message, &length, &algString))
		return NULL;

	

	HCRYPTPROV hProv;
	HCRYPTHASH hHash = 0;
	DWORD cbHash = 0;

	ALG_ID algId = GetAlgId(algString);

	if (!algId) {
		PyErr_Format(PyExc_ValueError, "Unexpected algorithm: %ls", algString);
		return NULL;
	}

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)) {
		PyErr_SetString(PyExc_Exception, "CryptAcquireContext failed");
		return NULL;
	}

	if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
		CryptReleaseContext(hProv, 0);
		PyErr_SetString(PyExc_Exception, "CryptCreateHash failed");
		return NULL;
	}

	BYTE* pbData = (BYTE*)message;

	if (!CryptHashData(hHash, pbData, (DWORD)length, 0)) {
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		PyErr_SetString(PyExc_Exception, "CryptHashData failed");
		return NULL;
	}

	cbHash = 64;
	BYTE rgbHash[64];

	if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		PyErr_SetString(PyExc_Exception, "CryptGetHashParam failed");
		return NULL;
	}

	DWORD hashStringSize;
	CryptBinaryToStringW(rgbHash, cbHash, CRYPT_STRING_HEX, NULL, &hashStringSize);

	std::vector<wchar_t> hashString(hashStringSize);
	CryptBinaryToStringW(rgbHash, cbHash, CRYPT_STRING_HEX, hashString.data(), &hashStringSize);

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	return PyUnicode_FromWideChar(hashString.data(), hashStringSize - 1);
}

std::vector<wchar_t> utf8ToWide(wchar_t * src) {
	// Original multi-byte string (UTF-8 encoded)
	const char* multiByteString = (const char*) src;

	// Determine the required buffer size for the wide-character string
	// Pass NULL for lpWideCharStr and 0 for cchWideChar to get the required size
	int wideCharSize = MultiByteToWideChar(
		CP_UTF8,         // Code page for the input string (UTF-8 in this case)
		0,               // dwFlags (no special flags for this example)
		multiByteString, // Pointer to the multi-byte string
		-1,              // cbMultiByte: -1 indicates null-terminated string
		NULL,            // lpWideCharStr: NULL to get required size
		0                // cchWideChar: 0 to get required size
	);

	if (wideCharSize == 0) {
		std::cerr << "Error determining wide character string size: " << GetLastError() << std::endl;
		exit(1);
	}

	// Allocate buffer for the wide-character string
	std::vector<wchar_t> wideCharBuffer(wideCharSize);

	// Perform the conversion
	int convertedChars = MultiByteToWideChar(
		CP_UTF8,
		0,
		multiByteString,
		-1,
		wideCharBuffer.data(), // Pointer to the wide-character buffer
		wideCharSize           // Size of the wide-character buffer
	);

	if (convertedChars == 0) {
		std::cerr << "Error converting multi-byte to wide character string: " << GetLastError() << std::endl;
		return wideCharBuffer;
	}
		
	return wideCharBuffer;
}

static PyObject* GetCertBySubject(PyObject* self, PyObject* args) {
	char* _storeName = nullptr;
	char* _subject = nullptr;

	if (!PyArg_ParseTuple(args, "ss", &_storeName, &_subject))
		return NULL;

	wchar_t* storeName = stringConverter.convertFromUTF8(_storeName);
	wchar_t* subject = stringConverter.convertFromUTF8(_subject);

	HCERTSTORE hStoreHandle;
	PCCERT_CONTEXT pCertContext = NULL;

	hStoreHandle = CertOpenSystemStoreW(0, storeName);
	pCertContext = CertFindCertificateInStore(hStoreHandle, MY_ENCODING_TYPE, 0, CERT_FIND_SUBJECT_STR_W, subject, NULL);

	if (!pCertContext) {
		PyErr_SetString(CertDoesNotExist, "Could not find the desired certificate.");
		CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
		return NULL;
	}

	PyObject* certInfo = GetCertInfo(pCertContext);

	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);

	return certInfo;
}

static PyObject* GetCertByThumbprint(PyObject* self, PyObject* args) {
	char* _storeName = nullptr;
	char* _thumbprint = nullptr;

	if (!PyArg_ParseTuple(args, "ss", &_storeName, &_thumbprint))
		return NULL;

	wchar_t* storeName = stringConverter.convertFromUTF8(_storeName);
	wchar_t* thumbprint = stringConverter.convertFromUTF8(_thumbprint);

	HCERTSTORE hStoreHandle;
	PCCERT_CONTEXT pCertContext = NULL;

	BYTE pDest[64]; // ��������� ��� ���� (����. 64 ����� ��� 512-������� ����)
	DWORD nOutLen = sizeof(pDest);

	if (!CryptStringToBinaryW(thumbprint, (DWORD)wcslen(thumbprint), CRYPT_STRING_HEX, pDest, &nOutLen, 0, 0)) {
		PyErr_SetString(PyExc_Exception, "CryptStringToBinaryW failed.");
		return NULL;
	}

	CRYPT_HASH_BLOB para;
	para.pbData = pDest;
	para.cbData = nOutLen;

	hStoreHandle = CertOpenSystemStoreW(0, storeName);
	pCertContext = CertFindCertificateInStore(hStoreHandle, MY_ENCODING_TYPE, 0, CERT_FIND_HASH, &para, NULL);

	if (!pCertContext) {
		CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
		PyErr_SetString(CertDoesNotExist, "Could not find the desired certificate.");
		return NULL;
	}

	PyObject* certInfo = GetCertInfo(pCertContext);

	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);

	return certInfo;
}

static PyObject* GetSignerCertFromSignature(PyObject* self, PyObject* args) {
	const char* signature;
	Py_ssize_t signatureLength;

	if (!PyArg_ParseTuple(args, "s#", &signature, &signatureLength))
		return NULL;

	BYTE* pDecodedSignContent = (BYTE*)signature;
	HCRYPTMSG hMsg;
	hMsg = CryptMsgOpenToDecode(MY_ENCODING_TYPE, 0, 0, 0, 0, 0);

	if (!hMsg) {
		PyErr_SetString(PyExc_Exception, "CryptMsgOpenToDecode failed.");
		return NULL;
	}

	if (!CryptMsgUpdate(hMsg, pDecodedSignContent, (DWORD)signatureLength, FALSE)) {
		CryptMsgClose(hMsg);
		PyErr_SetString(PyExc_Exception, "CryptMsgUpdate failed.");
		return NULL;
	}

	DWORD cbSignerCertInfo;
	if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &cbSignerCertInfo)) {
		CryptMsgClose(hMsg);
		PyErr_SetString(PyExc_Exception, "CryptMsgGetParam #1 failed.");
		return NULL;
	}

	PCERT_INFO pSignerCertInfo = (PCERT_INFO)malloc(cbSignerCertInfo);
	if (!pSignerCertInfo) {
		CryptMsgClose(hMsg);
		PyErr_SetString(PyExc_Exception, "Memory allocation failed.");
		return NULL;
	}

	if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, pSignerCertInfo, &cbSignerCertInfo)) {
		free(pSignerCertInfo);
		CryptMsgClose(hMsg);
		PyErr_SetString(PyExc_Exception, "CryptMsgGetParam #2 failed.");
		return NULL;
	}

	HCERTSTORE hStoreHandle = CertOpenStore(CERT_STORE_PROV_MSG, MY_ENCODING_TYPE, 0, 0, hMsg);
	if (!hStoreHandle) {
		free(pSignerCertInfo);
		CryptMsgClose(hMsg);
		PyErr_SetString(PyExc_Exception, "CertOpenStore failed.");
		return NULL;
	}

	PCCERT_CONTEXT pSignerCertContext = CertGetSubjectCertificateFromStore(hStoreHandle, MY_ENCODING_TYPE, pSignerCertInfo);
	free(pSignerCertInfo);

	if (!pSignerCertContext) {
		CertCloseStore(hStoreHandle, 0);
		CryptMsgClose(hMsg);
		PyErr_SetString(PyExc_Exception, "CertGetSubjectCertificateFromStore failed.");
		return NULL;
	}

	PyObject* certInfo = GetCertInfo(pSignerCertContext);

	CertFreeCertificateContext(pSignerCertContext);
	CertCloseStore(hStoreHandle, 0);
	CryptMsgClose(hMsg);

	return certInfo;
}

static PyObject* InstallCertificate(PyObject* self, PyObject* args) {
	char* _storeName = nullptr;
	const char* certData;
	Py_ssize_t certDataLength;

	if (!PyArg_ParseTuple(args, "sy#", &_storeName, &certData, &certDataLength))
		return NULL;

	wchar_t* storeName = stringConverter.convertFromUTF8(_storeName);

	BYTE* pDecodedCertData = (BYTE*)certData;
	PCCERT_CONTEXT pCertContext;
	pCertContext = CertCreateCertificateContext(MY_ENCODING_TYPE, pDecodedCertData, (DWORD)certDataLength);

	if (!pCertContext) {
		PyErr_SetString(PyExc_Exception, "Can't create cert context.");
		return NULL;
	}

	HCERTSTORE hStore;
	hStore = CertOpenSystemStoreW(0, storeName);
	if (!hStore) {
		CertFreeCertificateContext(pCertContext);
		PyErr_SetString(PyExc_Exception, "CertOpenSystemStoreW failed.");
		return NULL;
	}

	if (!CertAddCertificateContextToStore(hStore, pCertContext, CERT_STORE_ADD_USE_EXISTING, NULL)) {
		CertFreeCertificateContext(pCertContext);
		CertCloseStore(hStore, 0);
		PyErr_SetString(PyExc_Exception, "CertAddCertificateContextToStore failed.");
		return NULL;
	}

	PyObject* certInfo = GetCertInfo(pCertContext);

	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hStore, 0);

	return certInfo;
}

static PyObject* DeleteCertificate(PyObject* self, PyObject* args) {
	char* _storeName = nullptr;
	char* _thumbprint = nullptr;

	if (!PyArg_ParseTuple(args, "ss", &_storeName, &_thumbprint))
		return NULL;

	wchar_t* storeName = stringConverter.convertFromUTF8(_storeName);
	wchar_t* thumbprint = stringConverter.convertFromUTF8(_thumbprint);

	HCERTSTORE hStore;
	PCCERT_CONTEXT pCertContext = NULL;

	BYTE pDest[64];
	DWORD nOutLen = sizeof(pDest);

	if (!CryptStringToBinaryW(thumbprint, (DWORD)wcslen(thumbprint), CRYPT_STRING_HEX, pDest, &nOutLen, 0, 0)) {
		PyErr_SetString(PyExc_Exception, "CryptStringToBinaryW failed.");
		return NULL;
	}

	CRYPT_HASH_BLOB para;
	para.pbData = pDest;
	para.cbData = nOutLen;

	hStore = CertOpenSystemStoreW(0, storeName);
	pCertContext = CertFindCertificateInStore(hStore, MY_ENCODING_TYPE, 0, CERT_FIND_HASH, &para, NULL);

	if (!pCertContext) {
		CertCloseStore(hStore, 0);
		PyErr_SetString(CertDoesNotExist, "Could not find the desired certificate.");
		return NULL;
	}

	if (!CertDeleteCertificateFromStore(pCertContext)) {
		CertFreeCertificateContext(pCertContext);
		CertCloseStore(hStore, 0);
		PyErr_SetString(PyExc_Exception, "CertDeleteCertificateFromStore failed.");
		return NULL;
	}

	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hStore, 0);

	Py_RETURN_NONE;
}

static PyObject * Verify(PyObject *self, PyObject *args) {
    const char *signature;
    Py_ssize_t signatureLength;

    if (!PyArg_ParseTuple(args, "y#", &signature, &signatureLength))
        return NULL;

    PyObject * res = PyDict_New();

    PyDict_SetItemString(res, "verificationStatus", PyLong_FromLong(-1));
    PyDict_SetItemString(res, "message", Py_None);
    PyDict_SetItemString(res, "error", Py_None);


    CRYPT_VERIFY_MESSAGE_PARA cryptVerifyPara = { sizeof(cryptVerifyPara) };
    cryptVerifyPara.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;

    CADES_VERIFICATION_PARA cadesVerifyPara = { sizeof(cadesVerifyPara) };
    cadesVerifyPara.dwCadesType = CADES_BES;

    CADES_VERIFY_MESSAGE_PARA verifyPara = { sizeof(verifyPara) };

    verifyPara.pVerifyMessagePara = &cryptVerifyPara;
    verifyPara.pCadesVerifyPara = &cadesVerifyPara;

    BYTE *pbSignature = (BYTE*)signature;

    PCADES_VERIFICATION_INFO pVerifyInfo;
    PCRYPT_DATA_BLOB pContent = 0;

    if (!CadesVerifyMessage(&verifyPara, 0, pbSignature, signatureLength, &pContent, &pVerifyInfo)) {
        PyDict_SetItemString(res, "error", PyUnicode_FromFormat("0x%x", GetLastError()));
    }

    if (pVerifyInfo) {
        PyDict_SetItemString(res, "verificationStatus", PyLong_FromLong(pVerifyInfo->dwStatus));
        PyDict_SetItemString(res, "certInfo", GetCertInfo(pVerifyInfo->pSignerCert));
        PyDict_SetItemString(res, "signingTime", FileTimeToPyDateTime(pVerifyInfo->pSigningTime));

        if (pVerifyInfo->dwStatus == 0) {
            DWORD contentLength = 0;

            if(!CryptBinaryToString(pContent->pbData, pContent->cbData, CRYPT_STRING_BASE64, NULL, &contentLength)) {
                CadesFreeVerificationInfo(pVerifyInfo);
                PyErr_Format(PyExc_ValueError, "CryptBinaryToString #1 failed (error 0x%x).", GetLastError());
                return NULL;
            }

            std::vector<char> base64Content(contentLength+1);

            if(!CryptBinaryToString(pContent->pbData, pContent->cbData, CRYPT_STRING_BASE64, base64Content.data(), &contentLength)) {
                CadesFreeVerificationInfo(pVerifyInfo);
                PyErr_Format(PyExc_ValueError, "CryptBinaryToString #2 failed (error 0x%x).", GetLastError());
                return NULL;
            }

            PyDict_SetItemString(res, "message", PyUnicode_FromString(base64Content.data()));
        }

        CadesFreeVerificationInfo(pVerifyInfo);
    }

    return res;
}

static PyObject * VerifyDetached(PyObject *self, PyObject *args)
{
    const char *message;
    Py_ssize_t messageLength;
    const char *signature;
    Py_ssize_t signatureLength;

    if (!PyArg_ParseTuple(args, "y#y#", &message, &messageLength, &signature, &signatureLength))
        return NULL;

    PyObject * res = PyDict_New();

    PyDict_SetItemString(res, "verificationStatus", PyLong_FromLong(-1));
    PyDict_SetItemString(res, "error", Py_None);

    const BYTE *MessageArray[1];
    DWORD MessageSizeArray[1];

    BYTE *pbToBeSigned = (BYTE*)message;

    MessageArray[0] = pbToBeSigned;
    MessageSizeArray[0] = messageLength;

    CRYPT_VERIFY_MESSAGE_PARA cryptVerifyPara = { sizeof(cryptVerifyPara) };
    cryptVerifyPara.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;

    CADES_VERIFICATION_PARA cadesVerifyPara = { sizeof(cadesVerifyPara) };
    cadesVerifyPara.dwCadesType = CADES_BES;

    CADES_VERIFY_MESSAGE_PARA verifyPara = { sizeof(verifyPara) };

    verifyPara.pVerifyMessagePara = &cryptVerifyPara;
    verifyPara.pCadesVerifyPara = &cadesVerifyPara;

    PCADES_VERIFICATION_INFO pVerifyInfo;

    BYTE *pbSignature = (BYTE*)signature;

    if (!CadesVerifyDetachedMessage(&verifyPara, 0, pbSignature, signatureLength, 1, MessageArray, MessageSizeArray, &pVerifyInfo)) {
        PyDict_SetItemString(res, "error", PyUnicode_FromFormat("0x%x", GetLastError()));
    }

    if (pVerifyInfo) {
        PyDict_SetItemString(res, "verificationStatus", PyLong_FromLong(pVerifyInfo->dwStatus));
        PyDict_SetItemString(res, "certInfo", GetCertInfo(pVerifyInfo->pSignerCert));
        PyDict_SetItemString(res, "signingTime", FileTimeToPyDateTime(pVerifyInfo->pSigningTime));

        CadesFreeVerificationInfo(pVerifyInfo);
    }

    return res;
}

static PyObject* Sign(PyObject* self, PyObject* args) {
	const char* message;
	Py_ssize_t length;
	char* _thumbprint = nullptr;
	char* _storeName = nullptr;
	int detached;

	if (!PyArg_ParseTuple(args, "y#ssi", &message, &length, &_thumbprint, &_storeName, &detached))
		return NULL;

	wchar_t* thumbprint = stringConverter.convertFromUTF8(_thumbprint);
	wchar_t* storeName = stringConverter.convertFromUTF8(_storeName);

	HCERTSTORE hStoreHandle;
	PCCERT_CONTEXT pCertContext = NULL;

	BYTE pDest[64];
	DWORD nOutLen = sizeof(pDest);

	if (!CryptStringToBinaryW(thumbprint, (DWORD)wcslen(thumbprint), CRYPT_STRING_HEX, pDest, &nOutLen, 0, 0)) {
		PyErr_Format(PyExc_ValueError, "CryptStringToBinaryW #1 failed (error 0x%x).", GetLastError());
		return NULL;
	}

	CRYPT_HASH_BLOB para;
	para.pbData = pDest;
	para.cbData = nOutLen;

	hStoreHandle = CertOpenSystemStoreW(0, storeName);
	pCertContext = CertFindCertificateInStore(hStoreHandle, MY_ENCODING_TYPE, 0, CERT_FIND_HASH, &para, NULL);

	if (!pCertContext) {
		CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
		PyErr_Format(PyExc_ValueError, "CertFindCertificateInStore failed (error 0x%x).", GetLastError());
		return NULL;
	}

	CRYPT_SIGN_MESSAGE_PARA signPara = { sizeof(signPara) };
	signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
	signPara.pSigningCert = pCertContext;
	signPara.HashAlgorithm.pszObjId = GetHashOidByKeyOid(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
	signPara.rgpMsgCert = &pCertContext;
	signPara.cMsgCert = 1;

	CADES_SIGN_PARA cadesSignPara = { sizeof(cadesSignPara) };
	cadesSignPara.dwCadesType = CADES_BES;

	CADES_SIGN_MESSAGE_PARA messagePara = { sizeof(messagePara) };
	messagePara.pSignMessagePara = &signPara;
	messagePara.pCadesSignPara = &cadesSignPara;

	PCRYPT_DATA_BLOB pSignedMessage = 0;

	const BYTE* MessageArray[1];
	DWORD MessageSizeArray[1];

	BYTE* pbToBeSigned = (BYTE*)message;
	MessageArray[0] = pbToBeSigned;
	MessageSizeArray[0] = (DWORD)length;

	if (!CadesSignMessage(&messagePara, detached, 1, MessageArray, MessageSizeArray, &pSignedMessage)) {
		CertFreeCertificateContext(pCertContext);
		CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
		PyErr_Format(PyExc_ValueError, "CadesSignMessage failed (error 0x%x).", GetLastError());
		return NULL;
	}

	DWORD base64SignSize = 0;
	if (!CryptBinaryToStringW(pSignedMessage->pbData, pSignedMessage->cbData, CRYPT_STRING_BASE64, NULL, &base64SignSize)) {
		LocalFree(pSignedMessage);
		CertFreeCertificateContext(pCertContext);
		CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
		PyErr_Format(PyExc_ValueError, "CryptBinaryToStringW #1 failed (error 0x%x).", GetLastError());
		return NULL;
	}

	std::vector<wchar_t> base64SignValue(base64SignSize);
	if (!CryptBinaryToStringW(pSignedMessage->pbData, pSignedMessage->cbData, CRYPT_STRING_BASE64, base64SignValue.data(), &base64SignSize)) {
		LocalFree(pSignedMessage);
		CertFreeCertificateContext(pCertContext);
		CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
		PyErr_Format(PyExc_ValueError, "CryptBinaryToStringW #2 failed (error 0x%x).", GetLastError());
		return NULL;
	}

	LocalFree(pSignedMessage);
	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);

	return PyUnicode_FromWideChar(base64SignValue.data(), base64SignSize - 1);
}


static PyObject* EnumerateStore(PyObject* self, PyObject* args)
{
	char* _storeName = nullptr;

	if (!PyArg_ParseTuple(args, "s", &_storeName))
		return NULL;

	wchar_t* storeName = stringConverter.convertFromUTF8(_storeName);
	
	HCERTSTORE hStoreHandle = CertOpenSystemStoreW(0, storeName);
	PCCERT_CONTEXT  pCertContext = NULL;

	if (!hStoreHandle) {		
		PyErr_SetString(PyExc_Exception, "CertOpenStore failed.");
		return NULL;
	}

	PyObject* res = PyList_New(0);



	while (pCertContext = CertEnumCertificatesInStore(hStoreHandle,pCertContext)) 
	{
		auto info = GetCertInfo(pCertContext);
		PyList_Append(res, info);
	} 

	if (!CertCloseStore(hStoreHandle,0))
	{
		Py_DECREF(res);
		PyErr_SetString(PyExc_Exception, "CertCloseStore failed.");
		return NULL;
	}


	

	return res;
}

static PyMethodDef Methods[] = {
    {"create_hash", CreateHash, METH_VARARGS},
	{"enumerate_store", EnumerateStore, METH_VARARGS},
    {"get_cert_by_subject", GetCertBySubject, METH_VARARGS},
    {"get_cert_by_thumbprint", GetCertByThumbprint, METH_VARARGS},
    {"get_signer_cert_from_signature", GetSignerCertFromSignature, METH_VARARGS},
    {"install_certificate", InstallCertificate, METH_VARARGS},
    {"delete_certificate", DeleteCertificate, METH_VARARGS},
    {"verify", Verify, METH_VARARGS},
    {"verify_detached", VerifyDetached, METH_VARARGS},
    {"sign", Sign, METH_VARARGS},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef libpycades = {
    PyModuleDef_HEAD_INIT,
    "libpycades",
    NULL,
    -1,
    Methods
};

PyMODINIT_FUNC PyInit_libpycades(void)
{
    PyObject *m;
    m = PyModule_Create(&libpycades);

    CertDoesNotExist = PyErr_NewException("libpycades.CertDoesNotExist", NULL, NULL);
    Py_INCREF(CertDoesNotExist);
    PyModule_AddObject(m, "CertDoesNotExist", CertDoesNotExist);

    return m;
}

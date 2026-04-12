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
#include <algorithm>

#include <windows.h> // Required for MultiByteToWideChar
#include <iostream>  // For console output

#include "utils.h"

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "amd64/cades.lib")



#define CERT_NAME_STR_TYPE (CERT_X500_NAME_STR | CERT_NAME_STR_CRLF_FLAG)

#include "strings_helper.h"

PyObject* CertDoesNotExist = NULL;

// start helpers -------------------------------------------------------------------------------------------------------



static std::vector<BYTE> raw_to_der_gost256(const BYTE* raw_sig) {
	
	

	auto encodeInteger = [](const uint8_t* data, size_t len) -> std::vector<uint8_t> {
		std::vector<uint8_t> out;
		out.push_back(0x02); // INTEGER tag

		size_t val_len = len;
		if (data[0] & 0x80) {
			// нужно добавить leading zero
			out.push_back(static_cast<uint8_t>(len + 1));
			out.push_back(0x00);
			out.insert(out.end(), data, data + len);
		}
		else {
			out.push_back(static_cast<uint8_t>(len));
			out.insert(out.end(), data, data + len);
		}
		return out;
		};

	auto r_enc = encodeInteger(raw_sig, 32);
	auto s_enc = encodeInteger(raw_sig + 32, 32);

	size_t total_len = r_enc.size() + s_enc.size();
	std::vector<uint8_t> der;
	der.push_back(0x30); // SEQUENCE
	if (total_len < 128) {
		der.push_back(static_cast<uint8_t>(total_len));
	}
	else {
		// Для ГОСТ-256 total_len <= 68, так что этого не будет
		// Но для полноты: multi-byte length encoding при total_len >= 128
	}
	der.insert(der.end(), r_enc.begin(), r_enc.end());
	der.insert(der.end(), s_enc.begin(), s_enc.end());

	return der;
}


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

	Py_INCREF(Py_None);
    return Py_None;
}

PyObject * GetCertInfo(PCCERT_CONTEXT pCertContext) {
	PyObject* certInfo = PyDict_New();

	PyObject* subject = GetCertName(pCertContext->pCertInfo->Subject);
	PyDict_SetItemString(certInfo, "subject", subject);
	Py_DECREF(subject);

	PyObject* issuer = GetCertName(pCertContext->pCertInfo->Issuer);
	PyDict_SetItemString(certInfo, "issuer", issuer);
	Py_DECREF(issuer);

	PyObject* notBefore = FileTimeToPyDateTime(&pCertContext->pCertInfo->NotBefore);
	PyDict_SetItemString(certInfo, "notValidBefore", notBefore);
	Py_DECREF(notBefore);

	PyObject* notAfter = FileTimeToPyDateTime(&pCertContext->pCertInfo->NotAfter);
	PyDict_SetItemString(certInfo, "notValidAfter", notAfter);
	Py_DECREF(notAfter);

	PyObject* thumbprint = GetThumbprint(pCertContext);
	PyDict_SetItemString(certInfo, "thumbprint", thumbprint);
	Py_DECREF(thumbprint);

	PyObject* altName = GetCertAltName(pCertContext);
	PyDict_SetItemString(certInfo, "altName", altName);
	Py_DECREF(altName);

	PyObject* der_data = PyBytes_FromStringAndSize(
		(const char*)pCertContext->pbCertEncoded,
		pCertContext->cbCertEncoded
	);
	PyDict_SetItemString(certInfo, "der_data", der_data);
	Py_DECREF(der_data);

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
	CryptBinaryToStringW(rgbHash, cbHash, CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF, NULL, &hashStringSize);

	std::vector<wchar_t> hashString(hashStringSize);
	CryptBinaryToStringW(rgbHash, cbHash, CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF, hashString.data(), &hashStringSize);

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	return PyUnicode_FromWideChar(hashString.data(), hashStringSize);
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

    if (!CadesVerifyMessage(&verifyPara, 0, pbSignature, (DWORD)signatureLength, &pContent, &pVerifyInfo)) {
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
    MessageSizeArray[0] = (DWORD)messageLength;

    CRYPT_VERIFY_MESSAGE_PARA cryptVerifyPara = { sizeof(cryptVerifyPara) };
    cryptVerifyPara.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;

    CADES_VERIFICATION_PARA cadesVerifyPara = { sizeof(cadesVerifyPara) };
    cadesVerifyPara.dwCadesType = CADES_BES;

    CADES_VERIFY_MESSAGE_PARA verifyPara = { sizeof(verifyPara) };

    verifyPara.pVerifyMessagePara = &cryptVerifyPara;
    verifyPara.pCadesVerifyPara = &cadesVerifyPara;

    PCADES_VERIFICATION_INFO pVerifyInfo;

    BYTE *pbSignature = (BYTE*)signature;

    if (!CadesVerifyDetachedMessage(&verifyPara, 0, pbSignature, (DWORD)signatureLength, 1, MessageArray, MessageSizeArray, &pVerifyInfo)) {
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

static PyObject* VerifyHash(PyObject* self, PyObject* args)
{

	const char* hash_data;
	Py_ssize_t hash_len;

	const char* sign_data;
	Py_ssize_t sign_len;
	char* _thumbprint = nullptr;
	char* _storeName = nullptr;

	if (!PyArg_ParseTuple(args, "y#y#ss", &hash_data, &hash_len, &sign_data, &sign_len, &_thumbprint, &_storeName))
		return NULL;

	// DebugData("VerifyHash() hash_data", hash_data, hash_len);

	auto certificateData = GetCertificateData(_storeName, _thumbprint);

	if (!certificateData)	
		return NULL;
	
	auto keyContext = GetPrivateKeyContext(certificateData);

	if (!keyContext)
	{
		ReleaseCertificateData(certificateData);
		return NULL;
	}

	BOOL isValid = false;

	if (!keyContext->bIsCNG)
	{
		printf("Doing CryptAPI check...\n");
		HCRYPTHASH hHash = 0;
		auto algId = certificateData->getAlgId();

		//Проверяем ЭЦП
		CryptCreateHash((HCRYPTPROV)keyContext->hKey, algId, 0, 0, &hHash);
		CryptHashData(hHash, (BYTE*)hash_data, (DWORD)hash_len, 0);

		HCRYPTKEY k;

		CryptImportPublicKeyInfo((HCRYPTPROV)keyContext->hKey, 
			X509_ASN_ENCODING, 
			certificateData->PublicKeyInfo(), 
			&k);
		isValid = CryptVerifySignature(hHash, (const BYTE*)sign_data, (DWORD)sign_len, k, NULL, 0);
	}


	printf("CryptVerifySignature=%d\n", isValid);

	
	ReleasePrivateKeyContext(keyContext);
	ReleaseCertificateData(certificateData);

	if (isValid)
		return Py_True;
	else
		return Py_False;
}

static PyObject* SignHash(PyObject* self, PyObject* args) {
	const char* hash_data;
	Py_ssize_t hash_len;
	char* _thumbprint = nullptr;
	char* _storeName = nullptr;
	const char* output_format;

	if (!PyArg_ParseTuple(args, "y#sss", &hash_data, &hash_len, &_thumbprint, &_storeName, &output_format))
		return NULL;

	//DebugData("SignHash() hash_data", hash_data, hash_len);

	bool wantDer = (_stricmp(output_format, "der") == 0);

	wchar_t* thumbprint = stringConverter.convertFromUTF8(_thumbprint);
	wchar_t* storeName = stringConverter.convertFromUTF8(_storeName);

	HCERTSTORE hStore = NULL;
	PCCERT_CONTEXT pCertContext = NULL;

	// --- thumbprint hex -> binary
	BYTE thumbBin[64];
	DWORD thumbBinLen = sizeof(thumbBin);

	
	if (!CryptStringToBinaryW(
		thumbprint,
		(DWORD)wcslen(thumbprint),
		CRYPT_STRING_HEX,
		thumbBin,
		&thumbBinLen,
		NULL,
		NULL
	)) {
		PyErr_Format(PyExc_ValueError,
			"CryptStringToBinaryW failed (0x%x)", GetLastError());
		return NULL;
	}

	CRYPT_HASH_BLOB hashBlob;
	hashBlob.pbData = thumbBin;
	hashBlob.cbData = thumbBinLen;

	// --- open store & find cert
	hStore = CertOpenSystemStoreW(NULL, storeName);
	if (!hStore) {
		PyErr_Format(PyExc_ValueError,
			"CertOpenSystemStoreW failed (0x%x)", GetLastError());
		return NULL;
	}

	pCertContext = CertFindCertificateInStore(
		hStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_HASH,
		&hashBlob,
		NULL
	);

	if (!pCertContext) {
		CertCloseStore(hStore, 0);
		PyErr_Format(PyExc_ValueError,
			"CertFindCertificateInStore failed (0x%x)", GetLastError());
		return NULL;
	}

	// --- acquire private key
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
	DWORD dwKeySpec = 0;
	BOOL bFreeKey = FALSE;

	if (!CryptAcquireCertificatePrivateKey(
		pCertContext,
		CRYPT_ACQUIRE_SILENT_FLAG,
		NULL,
		&hKey,
		&dwKeySpec,
		&bFreeKey
	)) {
		CertFreeCertificateContext(pCertContext);
		CertCloseStore(hStore, 0);
		PyErr_Format(PyExc_ValueError,
			"CryptAcquireCertificatePrivateKey failed (0x%x)", GetLastError());
		return NULL;
	}

	

	std::vector<BYTE> signature;
	DWORD sigLen = 0;

	// ============================================================
	// ======================= CNG PATH ===========================
	// ============================================================
	if (dwKeySpec == CERT_NCRYPT_KEY_SPEC) {

		NCRYPT_KEY_HANDLE hNKey = (NCRYPT_KEY_HANDLE)hKey;

		SECURITY_STATUS status = NCryptSignHash(
			hNKey,
			NULL,
			(PBYTE)hash_data,
			(DWORD)hash_len,
			NULL,
			0,
			&sigLen,
			0
		);

		if (status != ERROR_SUCCESS) {
			if (bFreeKey) NCryptFreeObject(hNKey);
			CertFreeCertificateContext(pCertContext);
			CertCloseStore(hStore, 0);
			PyErr_Format(PyExc_Exception,
				"NCryptSignHash(size) failed (0x%x)", status);
			return NULL;
		}

		signature.resize(sigLen);

		status = NCryptSignHash(
			hNKey,
			NULL,
			(PBYTE)hash_data,
			(DWORD)hash_len,
			signature.data(),
			sigLen,
			&sigLen,
			0
		);

		BOOL verified = FALSE;
		status = NCryptVerifySignature(
			hNKey,
			NULL, // padding info — для ГОСТ должен быть NULL			
			(PBYTE)hash_data, (DWORD)hash_len,
			signature.data(), (DWORD)signature.size(),
			0
		);

		printf("Verified=%d\n", verified);

		if (status != ERROR_SUCCESS) {
			if (bFreeKey) NCryptFreeObject(hNKey);
			CertFreeCertificateContext(pCertContext);
			CertCloseStore(hStore, 0);
			PyErr_Format(PyExc_Exception,
				"NCryptSignHash failed (0x%x)", status);
			return NULL;
		}
	}
	// ============================================================
	// ======================= CSP PATH ===========================
	// ============================================================
	else {
		ALG_ID algId = 0;
		const char* oid =
			pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;

		if (strcmp(oid, szOID_CP_GOST_R3410EL) == 0)
			algId = CALG_GR3411;
		else if (strcmp(oid, szOID_CP_GOST_R3410_12_256) == 0)
			algId = CALG_GR3411_2012_256;
		else if (strcmp(oid, szOID_CP_GOST_R3410_12_512) == 0)
			algId = CALG_GR3411_2012_512;

		if (!algId) {
			if (bFreeKey) CryptReleaseContext(hKey, 0);
			CertFreeCertificateContext(pCertContext);
			CertCloseStore(hStore, 0);
			PyErr_SetString(PyExc_ValueError, "Unsupported CSP algorithm");
			return NULL;
		}

		HCRYPTHASH hHash = 0;

		if (!CryptCreateHash(
			(HCRYPTPROV)hKey,
			algId,
			0,
			0,
			&hHash
		)) {
			if (bFreeKey) CryptReleaseContext(hKey, 0);
			CertFreeCertificateContext(pCertContext);
			CertCloseStore(hStore, 0);
			PyErr_Format(PyExc_Exception,
				"CryptCreateHash failed (0x%x)", GetLastError());
			return NULL;
		}

		

		//if (!CryptSetHashParam(
		//	hHash,
		//	HP_HASHVAL,
		//	(BYTE*)hash_data,
		//	0
		//)) {
		//	CryptDestroyHash(hHash);
		//	if (bFreeKey) CryptReleaseContext(hKey, 0);
		//	CertFreeCertificateContext(pCertContext);
		//	CertCloseStore(hStore, 0);
		//	PyErr_Format(PyExc_Exception,
		//		"CryptSetHashParam failed (0x%x)", GetLastError());
		//	return NULL;
		//}

		CryptHashData(hHash, (BYTE*)hash_data,	(DWORD)hash_len, 0);

		CryptSignHash(
			hHash,
			dwKeySpec,
			NULL,
			0,
			NULL,
			&sigLen
		);

		

		signature.resize(sigLen);

		if (!CryptSignHash(
			hHash,
			dwKeySpec,
			NULL,
			0,
			signature.data(),
			&sigLen
		)) {
			CryptDestroyHash(hHash);
			if (bFreeKey) CryptReleaseContext(hKey, 0);
			CertFreeCertificateContext(pCertContext);
			CertCloseStore(hStore, 0);
			PyErr_Format(PyExc_Exception,
				"CryptSignHash failed (0x%x)", GetLastError());
			return NULL;
		}


		
 	//	if (sigLen == 64) {
 	//		// Инвертируем байты в r (первые 32 байта)
 	//		std::reverse(signature.begin(), signature.begin() + 32);
 	//		// Инвертируем байты в s (вторые 32 байта)
 	//		std::reverse(signature.begin() + 32, signature.end());
		//}

		CryptDestroyHash(hHash);
		

		//Проверяем ЭЦП
		CryptCreateHash((HCRYPTPROV)hKey, algId, 0, 0, &hHash);
		CryptHashData(hHash, (BYTE*)hash_data, (DWORD)hash_len, 0);

		HCRYPTKEY k;

		CryptImportPublicKeyInfo((HCRYPTPROV)hKey, X509_ASN_ENCODING, &pCertContext->pCertInfo->SubjectPublicKeyInfo, &k);
		BOOL r = CryptVerifySignature(hHash, (const BYTE*)signature.data(), (DWORD)signature.size(), k, NULL, 0);

		printf("CryptVerifySignature=%d\n", r);
		
	}

	// --- cleanup
	if (bFreeKey) {
		if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
			NCryptFreeObject(hKey);
		else
			CryptReleaseContext(hKey, 0);
	}

	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hStore, 0);

	if (wantDer && sigLen == 64) {		
		std::vector<BYTE> der = raw_to_der_gost256(signature.data());
		signature.swap(der);
		sigLen = (DWORD)signature.size();		
	}

	// Крипто-про разворачивает подпись, целую неделю промучался с этим
	std::reverse(signature.begin(), signature.end());

	return PyBytes_FromStringAndSize(
		(char*)signature.data(),
		sigLen
	);
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
	{"sign_hash", SignHash, METH_VARARGS},
	{"verify_hash", VerifyHash, METH_VARARGS},
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

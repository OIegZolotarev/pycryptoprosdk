#include <string>
#include <string.h>
#include <windows.h> // Required for MultiByteToWideChar
#include <iostream>

#include "strings_helper.h"

StringsConverter stringConverter;

StringsConverter::StringsConverter()
{

}

StringsConverter::~StringsConverter()
{

}

wchar_t* StringsConverter::convertFromUTF8(const char* multiByteString)
{
	int slot = poolIndex % POOL_SIZE;
	wchar_t* result = pool[slot];

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

	if (wideCharSize >= POOL_ENTRY_SIZE)
	{
		std::cerr << "UTF8 conversion error: wideCharSize >= POOL_ENTRY_SIZE" << GetLastError() << std::endl;
		exit(1);
	}



	// Perform the conversion
	int convertedChars = MultiByteToWideChar(
		CP_UTF8,
		0,
		multiByteString,
		-1,
		result, // Pointer to the wide-character buffer
		wideCharSize           // Size of the wide-character buffer
	);

	if (convertedChars == 0) {
		std::cerr << "Error converting multi-byte to wide character string: " << GetLastError() << std::endl;
		return result;
	}

	poolIndex++;
	return result;

}


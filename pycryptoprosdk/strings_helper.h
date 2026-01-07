
#define POOL_SIZE 16
#define POOL_ENTRY_SIZE 32768

class StringsConverter
{
	wchar_t pool[POOL_SIZE][POOL_ENTRY_SIZE];
	int poolIndex = 0;

public:
	StringsConverter();
	~StringsConverter();

	wchar_t* convertFromUTF8(const char* utf8String);
};

extern StringsConverter stringConverter;
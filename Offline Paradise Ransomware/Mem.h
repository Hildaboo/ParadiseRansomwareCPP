#pragma once
#include <Windows.h>


namespace Mem
{
   // �������� ������ ��������� �������.
	void *Alloc(size_t size);
	// ������������ ������ ��������� �������
	void *ReAlloc(void *mem2realloc, size_t size);
	// ������� ������.
	void Free(void* mem);
	// ��������� LPWSTR � LPSTR
	char    *Utf16toUtf8(wchar_t *utf16);
	// ��������� LPSTR � LPWSTR
	wchar_t *Utf8toUtf16(char *utf8);
	// �������� ������ �� src � dst.
	void __stdcall Copy(void* dst, const void* src, size_t size);
	// �������� ������ � mem.
	void Zero(void* mem, size_t size);
	// ��������� mem ������ c.
	void __stdcall Set(void* mem, char c, size_t size);
	// ���������� s1 � s2.
	int Compare(const void* s1, const void* s2, size_t size);
}


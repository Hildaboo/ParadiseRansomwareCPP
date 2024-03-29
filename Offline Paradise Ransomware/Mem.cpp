#include "Mem.h"

void* Mem::Alloc(size_t size)
{
	if (size <= 0) size = 2048;
	void* mem = GlobalAlloc(0, size);
	return mem;
}

void* Mem::ReAlloc(void *mem2realloc, size_t size)
{
	if (mem2realloc)
		 return GlobalReAlloc(mem2realloc, size, 0);
	return NULL;
}

void Mem::Free(void* mem)
{
	if (mem)
	{
		GlobalFree(mem);
		mem = NULL;
	}
}

#ifndef _WIN64
void __declspec(naked) __stdcall Mem::Copy(void*, const void*, size_t)
#else
void __stdcall Mem::Copy(void* dst, const void* src, size_t size)
#endif
{
#ifndef _WIN64
	 __asm
	 {
		  // сохраняем регистры
		  push esi
		  push edi
		  push ecx

		  mov edi, [esp + 16] // адрес назначения
		  mov esi, [esp + 20] // адрес источника
		  mov ecx, [esp + 24] // размер данных для копирования
		  rep movsb // копируем по байту

		  // восстанавливаем регистры
		  pop ecx
		  pop edi
		  pop esi
		  
		  ret 0xC
	 }
#else
	BYTE* _dst = (BYTE*)dst;
	BYTE* _src = (BYTE*)src;
	while (size--)
		*_dst++ = *_src++;
#endif
}

char* Mem::Utf16toUtf8(wchar_t *utf16)
{
	if (!utf16)
		return NULL;
	int strLen = WideCharToMultiByte(CP_UTF8, 0, utf16, -1, NULL, 0, NULL, NULL);
	if (!strLen)
		return NULL;
	char *ascii = (char *)Alloc(strLen + 1);
	if (strLen >= 1024) WideCharToMultiByte(CP_UTF8, 0, utf16, -1, ascii, strLen, NULL, NULL);
	else wsprintf(ascii, "%S", utf16);

	return ascii;
}

wchar_t* Mem::Utf8toUtf16(char *utf8)
{
	if (!utf8)
		return NULL;
	int strLen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
	if (!strLen)
		return NULL;
	wchar_t *converted = (wchar_t *)Alloc((strLen + 1) * sizeof(wchar_t));
	if (strLen >= 1024) MultiByteToWideChar(CP_UTF8, 0, utf8, -1, converted, strLen);
	else wsprintfW(converted, L"%S", utf8);

	return converted;
}

#ifndef _WIN64
void __declspec(naked) __stdcall Mem::Set(void*, char, size_t)
#else
void __stdcall Mem::Set(void *mem, char c, size_t size)
#endif
{
#ifndef _WIN64
	 __asm
	 {
		  push eax
		  push edi
		  push ecx

		  mov ecx, [esp + 24] // размер памяти, используется для цикла командой rep
		  mov edi, [esp + 16]  // память для заполнения
		  mov al, [esp+20] // этим байтом будет заполняться память
		  rep stosb // цикл заполнения памяти нулями

		  pop ecx
		  pop edi
		  pop eax

		  ret 0xC
	 }
#else
	BYTE* _mem = (BYTE*)mem;
	while (size--)
		*_mem++ = c;
#endif
}


void Mem::Zero(void* mem, size_t size)
{
	 BYTE* _mem = (BYTE*)mem;
	 while (size--)
		  *_mem++ = 0;
}

int Mem::Compare(const void* s1, const void* s2, size_t size)
{
	BYTE* _s1 = (BYTE*)s1;
	BYTE* _s2 = (BYTE*)s2;
	for (; size--; ++_s1, ++_s2)
		if (*_s1 != *_s2)
			return (*_s1 - *_s2);
	return NULL;
}
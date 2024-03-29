#pragma once
#include <Windows.h>


namespace Mem
{
   // Выделяет память заданного размера.
	void *Alloc(size_t size);
	// Перевыделяет память заданного размера
	void *ReAlloc(void *mem2realloc, size_t size);
	// Очищает память.
	void Free(void* mem);
	// Переводит LPWSTR в LPSTR
	char    *Utf16toUtf8(wchar_t *utf16);
	// Переводит LPSTR в LPWSTR
	wchar_t *Utf8toUtf16(char *utf8);
	// Копирует данные из src в dst.
	void __stdcall Copy(void* dst, const void* src, size_t size);
	// Обнуляет данные в mem.
	void Zero(void* mem, size_t size);
	// заполняет mem байтом c.
	void __stdcall Set(void* mem, char c, size_t size);
	// Сравнивает s1 с s2.
	int Compare(const void* s1, const void* s2, size_t size);
}


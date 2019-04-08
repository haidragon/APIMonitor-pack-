#pragma once

#include <Windows.h>
#include <shlwapi.h>
#pragma comment(lib,"shlwapi.lib")


#define  MAX_DEF_FILENAME_LENGTH 40


typedef struct _DefFileInfo
{
	WCHAR  szDefFileObject[MAX_PATH];			//模块名
	VOID*  lpMapAddress;						//映射地址
	DWORD  dwMapSize;							//占用大小
} DefFileInfo, *lpDefFileInfo;


BOOL	DoMapFile(WCHAR* szFileName, WCHAR* szDir);
VOID	UnmapSSFiles();
BOOL	ToNextLine(WCHAR* &pCh);
WCHAR*	GetApiParam(WCHAR* szDll, WCHAR* szApi, VOID* pStack);
BOOL	CreateSSMapFile();

BOOL	GetHookModel();

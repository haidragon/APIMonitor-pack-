#pragma once

#ifdef SHELLBASE_EXPORTS
#define SHELL_API __declspec(dllexport)
#else
#define SHELL_API __declspec(dllimport)
#endif

#include <windows.h>
#include <Winternl.h>
#include <stdint.h> 
#include "Algorithm.h"


#define		COMPRESS_APLIB				0x0
#define		COMPRESS_JCALG1_FAST		0x1
#define		COMPRESS_JCALG1_SMALL		0x2

typedef struct _ComPressInfo
{
	DWORD	OriginalRva;		//原区段的RVA
	DWORD	CompressRva;		//压缩后的RVA
	DWORD	CompressSize;		//压缩大小
	LPBYTE	pData;				//压缩数据指针
}ComPressInfo, *PComPressInfo;


typedef struct _SelectionInfo
{
	//基础部分
	BOOL	bIsCompression;
	DWORD	dwCompressionType;
	BOOL	bIsEncryption;
	BOOL	bIsTransferIAT;
	BOOL	bIsTransferReloc;

	//AntiCrack部分
	BOOL	bIsApiRedirect;			//IAT重定向
	BOOL	bIsAntiDebugging;		//反调试
	BOOL	bIsAntiDump;			//反Dump
	BOOL	bIsFusedCracker;		//混淆函数
	BOOL	bIsFileVerification;	//文件校验
	BOOL	bIsMemVerification;		//内存校验
	BOOL	bIsAntiOD;				//反OD

}SelectionInfo, *PSelectionInfo;


extern"C"  typedef struct _SHELL_DATA
{
	DWORD					dwPEOEP;			//程序入口点
	DWORD					dwOldOEP;			//原程序OEP
	DWORD					dwImageBase;		//PE文件默认映像基址
	DWORD					dwIATSectionBase;	//IAT所在段基址
	DWORD					dwIATSectionSize;	//IAT所在段大小
	DWORD					dwCodeBase;			//代码段基址
	DWORD					dwCodeSize;			//代码段大小
	DWORD					dwCodeRawSize;		//代码段大小（文件粒度）
	DWORD					dwNumOfSections;	//区段个数
	IMAGE_DATA_DIRECTORY	stcPERelocDir;		//重定位表信息
	IMAGE_DATA_DIRECTORY	stcPEImportDir;		//导入表信息
	IMAGE_DATA_DIRECTORY	stcIATDir;			//IAT信息
	IMAGE_DATA_DIRECTORY	stcPEResDir;		//资源表信息
	IMAGE_DATA_DIRECTORY	stcPETlsDir;		//tls表信息
	IMAGE_DATA_DIRECTORY	stcPETlsShellDir;	//宿主程序中shell的tls表信息
	BOOL					bTlsExist;			//使用了tls
	DWORD					dwOriginalSecRva;	//宿主程序原始节表的RVA
	DWORD					dwCompressInfoRva;	//宿主程序压缩结构体数组的RVA
	DWORD					dwNewIATRva;		//宿主程序转储后的IAT的RVA
	DWORD					dwNewRelocRva;		//苏主程序转储后的重定位表的RVA
	BOOL					bDll;				//宿主程序是否为DLL
	SelectionInfo			stcConfig;			//加壳操作的配置信息
	DWORD					dwCodeMemCRC32;		//代码段的CRC32值
	CHAR					szDllName[MAX_PATH];
}SHELL_DATA, *PSHELL_DATA;

//导出ShellData结构体变量
extern"C" SHELL_API SHELL_DATA g_stcShellData;


typedef DWORD(WINAPI *fnGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
typedef HMODULE(WINAPI *fnLoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef HMODULE(WINAPI *fnGetModuleHandleA)(_In_opt_ LPCSTR lpModuleName);
typedef BOOL(WINAPI *fnVirtualProtect)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
typedef LPVOID(WINAPI *fnVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
typedef void(WINAPI *fnExitProcess)(_In_ UINT uExitCode);
typedef int(WINAPI *fnMessageBox)(HWND hWnd, LPSTR lpText, LPSTR lpCaption, UINT uType);
typedef void(WINAPI* fnOutPutDebugString)(_In_opt_ LPCSTR lpOutputString);
typedef	BOOL(WINAPI* fnVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef DWORD(WINAPI* fnGetModuleFileNameA)(_In_opt_ HMODULE hModule, _Out_writes_to_(nSize, ((return < nSize) ? (return +1) : nSize)) LPSTR lpFilename,
	_In_ DWORD nSize);

typedef HANDLE (WINAPI* fnCreateFileA)(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
);

typedef DWORD (WINAPI* fnGetFileSize)(
	_In_ HANDLE hFile,
	_Out_opt_ LPDWORD lpFileSizeHigh
);

typedef BOOL (WINAPI* fnWriteFile)(
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);



typedef BOOL (WINAPI* fnReadFile)(
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);


typedef BOOL (WINAPI* fnCloseHandle)(
	_In_ _Post_ptr_invalid_ HANDLE hObject
);


typedef void*(__cdecl *fnMemset)(
	_Out_writes_bytes_all_(_Size) void*  _Dst,
	_In_                          int    _Val,
	_In_                          size_t _Size);

typedef void*(__cdecl *fnMemcpy)(
	_Out_writes_bytes_all_(_Size) void* _Dst,
	_In_reads_bytes_(_Size)       void const* _Src,
	_In_                          size_t      _Size);


typedef VOID (WINAPI* fnGetSystemInfo)(
	_Out_ LPSYSTEM_INFO lpSystemInfo
);


typedef SIZE_T (WINAPI* fnVirtualQuery)(
	_In_opt_ LPCVOID lpAddress,
	_Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
	_In_ SIZE_T dwLength
);





//////////////////////////////////////////////////////////////////////////
//	Anti-Dump所需结构体
//////////////////////////////////////////////////////////////////////////

typedef struct _MYPEB_LDR_DATA
{
	PVOID					Reserved1[3];
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} MYPEB_LDR_DATA, *PMYPEB_LDR_DATA;

typedef struct _MYLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} MYLDR_DATA_TABLE_ENTRY, *PMYLDR_DATA_TABLE_ENTRY;

typedef struct _MYRTL_USER_PROCESS_PARAMETERS
{
	ULONG                   MaximumLength;
	ULONG                   Length;
	ULONG                   Flags;
	ULONG                   DebugFlags;
	PVOID                   ConsoleHandle;
	ULONG                   ConsoleFlags;
	HANDLE                  StdInputHandle;
	HANDLE                  StdOutputHandle;
	HANDLE                  StdErrorHandle;
	UNICODE_STRING          CurrentDirectoryPath;
	HANDLE                  CurrentDirectoryHandle;
	UNICODE_STRING          DllPath;
	UNICODE_STRING          ImagePathName;
	UNICODE_STRING          CommandLine;
	PVOID                   Environment;
	ULONG                   StartingPositionLeft;
	ULONG                   StartingPositionTop;
	ULONG                   Width;
	ULONG                   Height;
	ULONG                   CharWidth;
	ULONG                   CharHeight;
	ULONG                   ConsoleTextAttributes;
	ULONG                   WindowFlags;
	ULONG                   ShowWindowFlags;
	UNICODE_STRING          WindowTitle;
	UNICODE_STRING          DesktopName;
	UNICODE_STRING          ShellInfo;
	UNICODE_STRING          RuntimeData;
}MYRTL_USER_PROCESS_PARAMETERS, *PMYRTL_USER_PROCESS_PARAMETERS;
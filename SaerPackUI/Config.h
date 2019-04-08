#pragma once
#include <winternl.h>

//压缩类型
#define		COMPRESS_APLIB				0x0
#define		COMPRESS_JCALG1_FAST		0x1
#define		COMPRESS_JCALG1_SMALL		0x2
 

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

	//试验功能
	BOOL	bIsVirtualizeCode;		//代码虚拟化
	WCHAR	szSample[MAX_PATH];

}SelectionInfo, *PSelectionInfo;

//typedef struct _MYPEB_LDR_DATA
//{
//	PVOID					Reserved1[3];
//	LIST_ENTRY              InLoadOrderModuleList;
//	LIST_ENTRY              InMemoryOrderModuleList;
//	LIST_ENTRY              InInitializationOrderModuleList;
//} MYPEB_LDR_DATA, *PMYPEB_LDR_DATA;
//
//
//typedef struct _MYLDR_DATA_TABLE_ENTRY
//{
//	LIST_ENTRY              InLoadOrderModuleList;
//	LIST_ENTRY              InMemoryOrderModuleList;
//	LIST_ENTRY              InInitializationOrderModuleList;
//	PVOID                   BaseAddress;
//	PVOID                   EntryPoint;
//	ULONG                   SizeOfImage;
//	UNICODE_STRING          FullDllName;
//	UNICODE_STRING          BaseDllName;
//	ULONG                   Flags;
//	SHORT                   LoadCount;
//	SHORT                   TlsIndex;
//	LIST_ENTRY              HashTableEntry;
//	ULONG                   TimeDateStamp;
//} MYLDR_DATA_TABLE_ENTRY, *PMYLDR_DATA_TABLE_ENTRY;


//////////////////////////////////////////////////////////////////////////
//	加壳总接口
//	参数：
//	_In_ LPWSTR				- 加壳文件的绝对地址
//	 _In_ PSelectionInfo	- 配置信息（压缩、加密、转储、AntiCrack的选择等）
//////////////////////////////////////////////////////////////////////////

typedef	BOOL(*fnPackBase)	(_In_ LPWSTR, _In_ PSelectionInfo);
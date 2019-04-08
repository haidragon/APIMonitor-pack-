// MyShell.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "ShellBase.h"
#include "aplib.h"
#include <jcalg1.h>
#include <udis86.h>


//#pragma comment(linker, "/entry:\"Start\"")
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/merge:.CRT=.text")
#pragma comment(linker, "/section:.text,RWE")



VOID	Start();													//启动函数(Shell部分的入口函数)
VOID	RECReloc();													//重定位修复
BOOL	RECNewReloc();												//转储重定位修复
VOID	RECIAT();													//IAT修复
BOOL	RECTNewIAT();												//转储IAT修复
VOID	DecrypetSection(LPBYTE, DWORD);								//解密指定段
DWORD	GetKernel32Addr();											//获取Kernel32加载基址
BOOL	GetShellApi();												//获取Shell所需API地址
DWORD	MyGetProcAddress();											//获取GetProcAddress
BOOL	CheckOutFirstThunk(HMODULE hMod,
		PIMAGE_IMPORT_DESCRIPTOR	pIAT);							//检查该DLL的FirstThunk是否特殊

VOID	InitiTLS(PIMAGE_TLS_DIRECTORY pTlsDirOfFile, PIMAGE_TLS_DIRECTORY pTlsDirOfShell);	//初始化TLS
LPBYTE	UnpackDataOfAplib(LPBYTE pPackedData, DWORD dwPackedSize, PDWORD	dwUnpackSize);	//解压
LPBYTE	UnpackDataOfJCALG1(LPBYTE pPackedData, DWORD dwPackedSize, PDWORD	dwUnpackSize, DWORD dwType);//解压
LPBYTE	RedirectIAT(CHAR* szDllName, DWORD dwFunAddr);				//重定位IAT表
VOID	DeComPress();												//解压总接口
BOOL	CleanUnicodeString(PUNICODE_STRING pUnicodeString);		

BOOL	SeachCharac(char* Charac, int Length);						//匹配特征串

BOOL	CodeMemVerification();										//内存校验
BOOL	FileVerification();											//文件校验


VOID			VirtualJmpOEP();
VOID			AntiDump();
VOID			AntiDebugging();
VOID _stdcall	FusedFunc(DWORD dwfuncAddress);						//混淆函数


SHELL_DATA				 g_stcShellData = { (DWORD)Start };

const WCHAR* szODCharac = L"OllyDBG";



extern uint32_t			 crc32_table[256];	// CRC32计算表格
extern BOOL				 g_Crc32Table;//是否生成了CRC32表格


fnGetProcAddress		g_pfnGetProcAddress		= NULL;
fnLoadLibraryA			g_pfnLoadLibraryA		= NULL;
fnGetModuleHandleA		g_pfnGetModuleHandleA	= NULL;
fnGetModuleFileNameA	g_pfnGetModuleFileNameA = NULL;
fnVirtualProtect		g_pfnVirtualProtect		= NULL;
fnVirtualAlloc			g_pfnVirtualAlloc		= NULL;
fnExitProcess			g_pfnExitProcess		= NULL;
fnMessageBox			g_pfnMessageBoxA		= NULL;
fnOutPutDebugString		g_pfnOutPutDebugString	= NULL;
fnVirtualFree			g_pfnVirtualFree		= NULL;
fnMemset				g_pfnMemset				= NULL;
fnMemcpy				g_pfnMemcpy				= NULL;
fnCreateFileA			g_pfnCreateFileA		= NULL;
fnGetFileSize			g_pfnGetFileSize		= NULL;
fnWriteFile				g_pfnWriteFile			= NULL;
fnReadFile				g_pfnReadFile			= NULL;
fnCloseHandle			g_pfnCloseHandle		= NULL;
fnGetSystemInfo			g_pfnGetSystemInfo		= NULL;
fnVirtualQuery			g_pfnVirtualQuery		= NULL;


DWORD					g_dwImageBase			= NULL;
static	BOOL			g_bFirstRun				= TRUE;


#define MyCopyMemory(Destination,Source,Length) g_pfnMemcpy((Destination),(Source),(Length))

#define MyZeroMemory(Destination,Length) g_pfnMemset((Destination),0,(Length))

__declspec (thread) int g_num;

//构造一个TLS机制
VOID	WINAPI	TlsCallBack(PVOID dwDllHandle, DWORD dwReason, PVOID pReserved)
{
	g_num;
}

#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK	pTlsCallBack[] = { TlsCallBack, NULL };
#pragma data_seg()




void __declspec(naked)   Start()
{	
	if (!g_bFirstRun)	goto SecondRun;

	g_bFirstRun = FALSE;

	__asm sub esp, 0x50

	if (g_stcShellData.stcConfig.bIsAntiDump)
		AntiDump();

	if (g_stcShellData.stcConfig.bIsAntiDebugging)
		AntiDebugging();

	if (g_stcShellData.stcConfig.bIsFusedCracker)
		FusedFunc((DWORD)GetShellApi);
	else
		GetShellApi();

	if (g_stcShellData.stcConfig.bIsCompression)
		if (!g_stcShellData.bTlsExist)
		{
			if (g_stcShellData.stcConfig.bIsFusedCracker)
				FusedFunc((DWORD)DeComPress);
			else
				DeComPress();
		}

	g_pfnMessageBoxA(NULL, "Shell By Saer .2018.3", "提示", 0);

	DecrypetSection((LPBYTE)(g_stcShellData.dwCodeBase + g_dwImageBase), g_stcShellData.dwCodeRawSize);

	goto Out;

TrueOEP:
	if (g_stcShellData.stcConfig.bIsFusedCracker)
	FusedFunc((DWORD)VirtualJmpOEP);
	else
	__asm call VirtualJmpOEP

Out:

	if (g_stcShellData.stcPERelocDir.VirtualAddress)
	{
		//是否转储了重定位表
		if (g_stcShellData.stcConfig.bIsTransferReloc)
		{
			if (g_stcShellData.stcConfig.bIsFusedCracker)
				FusedFunc((DWORD)RECNewReloc);
			else
				RECNewReloc();
		}
		else
		{
			if (g_stcShellData.stcConfig.bIsFusedCracker)
				FusedFunc((DWORD)RECReloc);
			else
				RECReloc();
		}
	}


	if (g_stcShellData.stcConfig.bIsTransferIAT)
	{	//是否转储了IAT表
		if (g_stcShellData.stcConfig.bIsFusedCracker)
			FusedFunc((DWORD)RECTNewIAT);
		else
			RECTNewIAT();
	}
	else
	{
		if (g_stcShellData.stcConfig.bIsFusedCracker)
			FusedFunc((DWORD)RECIAT);
		else
			RECIAT();
	}


	if (g_stcShellData.bTlsExist)
	{//tls存在的处理
		PIMAGE_TLS_DIRECTORY	pTlsFile;
		PIMAGE_TLS_DIRECTORY	pTlsShell;
		pTlsFile = (PIMAGE_TLS_DIRECTORY)(g_dwImageBase + g_stcShellData.stcPETlsDir.VirtualAddress);
		pTlsShell = (PIMAGE_TLS_DIRECTORY)(g_dwImageBase + g_stcShellData.stcPETlsShellDir.VirtualAddress);
		InitiTLS(pTlsFile, pTlsShell);
	}

	//文件校验
	if (g_stcShellData.stcConfig.bIsFileVerification)
		if (FileVerification() == FALSE)
		{
			g_pfnMessageBoxA(NULL, "File Verification Failed", NULL, NULL);
			g_pfnExitProcess(0x0);
		}
	

	//内存校验
	
	if (g_stcShellData.stcConfig.bIsMemVerification)
		if(!g_stcShellData.bTlsExist)
		if (CodeMemVerification() == FALSE)
		{
			g_pfnMessageBoxA(NULL, "Mem Verification Failed", NULL, NULL);
			g_pfnExitProcess(0x0);
		}


	//扫描特征串
	if(g_stcShellData.stcConfig.bIsAntiOD)
	if (SeachCharac((char*)szODCharac, wcslen(szODCharac) * sizeof(WCHAR)))
	{
		g_pfnMessageBoxA(NULL, "发现OD特征串", NULL, NULL);
		g_pfnExitProcess(0x0);
	}


	__asm add esp, 0x50

	SecondRun:

	goto TrueOEP;

	//DWORD	dwOldOEP;

	//dwOldOEP = g_stcShellData.dwPEOEP + g_dwImageBase;

	//__asm jmp dwOldOEP


	//if (g_pfnExitProcess)
	//{
	//	g_pfnExitProcess(0);
	//}
	

	__asm retn

}


////////////////////////////////////////////////////////////////////////////
//	将跳转原OEP封装到一个函数内，增加调试人员的分析成本
//////////////////////////////////////////////////////////////////////////

VOID VirtualJmpOEP()
{
	DWORD	dwOldOEP;

	dwOldOEP = g_stcShellData.dwOldOEP + g_dwImageBase;

	__asm jmp dwOldOEP


	if (g_pfnExitProcess)
	{
		g_pfnExitProcess(0);
	}

}


DWORD GetKernel32Addr()
{
	DWORD dwKernel32Base;
	__asm
	{
		xor ebx, ebx
		mov ebx, fs:[0x30]; PEB
		mov ebx, [ebx + 0x0C]; PEB->Ldr
		mov ebx, [ebx + 0x14]; PEB->Ldr.InMemoryOrderModuleList.Flink(1st entry)
		mov ebx, [ebx]; next entry(2nd entry)
		mov ebx, [ebx]; entry(3rd entry)
		mov ebx, [ebx + 0x10]; base address(kernel32.dll)
		mov dwKernel32Base, ebx
	}

	return dwKernel32Base;
}


BOOL GetShellApi()
{
	HMODULE dwKernel32Base;

	dwKernel32Base = (HMODULE)GetKernel32Addr();

	if (!(g_pfnGetProcAddress = (fnGetProcAddress)MyGetProcAddress()))
		return FALSE;
	if (!(g_pfnLoadLibraryA = (fnLoadLibraryA)g_pfnGetProcAddress(dwKernel32Base, "LoadLibraryA")))	
		return FALSE;
	if (!(g_pfnGetModuleHandleA = (fnGetModuleHandleA)g_pfnGetProcAddress(dwKernel32Base, "GetModuleHandleA")))
		return FALSE;
	if (!(g_pfnGetModuleFileNameA = (fnGetModuleFileNameA)g_pfnGetProcAddress(dwKernel32Base, "GetModuleFileNameA")))
		return FALSE;
	if (!(g_pfnVirtualProtect = (fnVirtualProtect)g_pfnGetProcAddress(dwKernel32Base, "VirtualProtect")))	
		return FALSE;
	if (!(g_pfnExitProcess = (fnExitProcess)g_pfnGetProcAddress(dwKernel32Base, "ExitProcess")))
		return FALSE;
	if (!(g_pfnVirtualAlloc = (fnVirtualAlloc)g_pfnGetProcAddress(dwKernel32Base, "VirtualAlloc")))
		return FALSE;
	if (!(g_pfnVirtualFree = (fnVirtualFree)g_pfnGetProcAddress(dwKernel32Base, "VirtualFree")))
		return FALSE;

	if (!(g_pfnCreateFileA = (fnCreateFileA)g_pfnGetProcAddress(dwKernel32Base, "CreateFileA")))
		return FALSE;
	if (!(g_pfnGetFileSize = (fnGetFileSize)g_pfnGetProcAddress(dwKernel32Base, "GetFileSize")))
		return FALSE;

	if (!(g_pfnWriteFile = (fnWriteFile)g_pfnGetProcAddress(dwKernel32Base, "WriteFile")))
		return FALSE;

	if (!(g_pfnReadFile = (fnReadFile)g_pfnGetProcAddress(dwKernel32Base, "ReadFile")))
		return FALSE;

	if (!(g_pfnCloseHandle = (fnCloseHandle)g_pfnGetProcAddress(dwKernel32Base, "CloseHandle")))
		return FALSE;


	if (!(g_pfnGetSystemInfo = (fnGetSystemInfo)g_pfnGetProcAddress(dwKernel32Base, "GetSystemInfo")))
		return FALSE;

	if (!(g_pfnVirtualQuery = (fnVirtualQuery)g_pfnGetProcAddress(dwKernel32Base, "VirtualQuery")))
		return FALSE;
		
	//////////////////////////////////////////////////////////////////////////

	if (!(g_pfnOutPutDebugString = (fnOutPutDebugString)g_pfnGetProcAddress(dwKernel32Base, "OutputDebugStringA")))
		return FALSE;


	HMODULE hUser32;

	hUser32 = g_pfnLoadLibraryA("user32.dll");

	if (!hUser32)
	{
		return FALSE;
	}

	if (!(g_pfnMessageBoxA = (fnMessageBox)g_pfnGetProcAddress(hUser32, "MessageBoxA")))	return FALSE;

	if (g_stcShellData.bDll)
	{
		g_dwImageBase = (DWORD)g_pfnGetModuleHandleA(g_stcShellData.szDllName);
	}
	else
	{
		g_dwImageBase = (DWORD)g_pfnGetModuleHandleA(NULL);
	}


	HMODULE hMod = g_pfnLoadLibraryA("MSVCRT.dll");

	if (!hMod)
	{
		g_pfnMessageBoxA(NULL, "核心模块加载失败！", "提示", NULL);
		return FALSE;
	}
	

	if (!(g_pfnMemset = (fnMemset)g_pfnGetProcAddress(hMod, "memset")))	return FALSE;

	if (!(g_pfnMemcpy = (fnMemcpy)g_pfnGetProcAddress(hMod, "memcpy")))	return FALSE;


	return TRUE;
}


void	RECReloc()
{
	typedef struct _TYPEOFFSET
	{
		WORD offset : 12;			//偏移值
		WORD Type : 4;			//重定位属性(方式)
	}TYPEOFFSET, *PTYPEOFFSET;


	PIMAGE_BASE_RELOCATION	pReloc = (PIMAGE_BASE_RELOCATION)(g_dwImageBase + g_stcShellData.stcPERelocDir.VirtualAddress);
	DWORD					dwRelocOfItemNum;
	DWORD					dwRVA;
	DWORD					dwItemAddressOfReloc;
	DWORD					dwOldProtect;
	PTYPEOFFSET				pOffset;


	while (pReloc->VirtualAddress)
	{
		dwRelocOfItemNum = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

		g_pfnVirtualProtect((LPBYTE)(g_dwImageBase + pReloc->VirtualAddress),
		0x2000, PAGE_EXECUTE_READWRITE, &dwOldProtect);

		pOffset = (PTYPEOFFSET)((DWORD)pReloc + sizeof(IMAGE_BASE_RELOCATION));
		for (DWORD i = 0; i < dwRelocOfItemNum; i++, pOffset++)
		{
			if (pOffset->Type != IMAGE_REL_BASED_HIGHLOW)
			continue;

			dwRVA = pReloc->VirtualAddress + pOffset->offset;
			dwItemAddressOfReloc = *(DWORD*)(dwRVA + g_dwImageBase);
			*(DWORD*)(dwRVA + g_dwImageBase) = dwItemAddressOfReloc - g_stcShellData.dwImageBase + g_dwImageBase;
		}


		g_pfnVirtualProtect((LPBYTE)(g_dwImageBase + pReloc->VirtualAddress),
		0x2000, dwOldProtect, &dwOldProtect);

		pReloc = (PIMAGE_BASE_RELOCATION)(pReloc->SizeOfBlock + (DWORD)pReloc);
	}


}



void	RECIAT()
{
	PIMAGE_IMPORT_DESCRIPTOR	pIAT;
	HMODULE						hMod;
	PIMAGE_THUNK_DATA			pThunk;
	PIMAGE_THUNK_DATA			pTrueThunk;			//可写操作的Thunk指针
	PIMAGE_IMPORT_BY_NAME		pImportByName;
	DWORD						dwIndex;
	DWORD						dwOldProtect;
	DWORD						dwFunAddr;
	BOOL						bRedirect = g_stcShellData.stcConfig.bIsApiRedirect;

	g_pfnVirtualProtect((LPVOID)(g_stcShellData.dwIATSectionBase + g_dwImageBase),
		g_stcShellData.dwIATSectionSize,
		PAGE_EXECUTE_READWRITE, &dwOldProtect);

	pIAT = (PIMAGE_IMPORT_DESCRIPTOR)(g_stcShellData.stcPEImportDir.VirtualAddress + g_dwImageBase);


	while (pIAT->Name)
	{
		hMod = g_pfnLoadLibraryA((CHAR*)(pIAT->Name + g_dwImageBase));

		//做一些对某些特殊dll的判断

		if (CheckOutFirstThunk(hMod, pIAT))
		{
			pThunk		= (PIMAGE_THUNK_DATA)(pIAT->FirstThunk + g_dwImageBase);
			pTrueThunk	= pThunk;
		}
		else
		{
			pThunk		= (PIMAGE_THUNK_DATA)(pIAT->OriginalFirstThunk + g_dwImageBase);
			pTrueThunk = (PIMAGE_THUNK_DATA)(pIAT->FirstThunk + g_dwImageBase);
		}
	
		while (pThunk->u1.AddressOfData)
		{
		
			if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
			{//序号
				dwIndex = pThunk->u1.Ordinal & 0x7FFFFFFF;
				dwFunAddr = (DWORD)g_pfnGetProcAddress(hMod, (CHAR*)dwIndex);
				if (bRedirect)
					*(DWORD*)pTrueThunk = (DWORD)RedirectIAT((CHAR*)(pIAT->Name + g_dwImageBase), dwFunAddr);
				else
					*(DWORD*)pTrueThunk = dwFunAddr;
			}
			else
			{//字符串
				pImportByName = (PIMAGE_IMPORT_BY_NAME)(pThunk->u1.AddressOfData + g_dwImageBase);
				dwFunAddr = (DWORD)g_pfnGetProcAddress(hMod, pImportByName->Name);
				if (bRedirect)
					*(DWORD*)pTrueThunk = (DWORD)RedirectIAT((CHAR*)(pIAT->Name + g_dwImageBase), dwFunAddr);
				else
					*(DWORD*)pTrueThunk = dwFunAddr;
			}

			pThunk++;
			pTrueThunk++;
		}

		pIAT++;
	}
		g_pfnVirtualProtect((LPVOID)(g_stcShellData.dwIATSectionBase + g_dwImageBase),
		g_stcShellData.dwIATSectionSize,
		dwOldProtect, &dwOldProtect);
}



void	DecrypetSection(LPBYTE pSectionBuf, DWORD dwSectionSize)
{
	DWORD	dwOldProtect;

	g_pfnVirtualProtect(pSectionBuf, dwSectionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	for (DWORD i = 0; i < dwSectionSize; i++)
	{
		pSectionBuf[i] ^= i;
	}

	g_pfnVirtualProtect(pSectionBuf, dwSectionSize, dwOldProtect, &dwOldProtect);

    	  
}



DWORD MyGetProcAddress()
{
	HMODULE hModule = (HMODULE)GetKernel32Addr();

	//1.获取DOS头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(PBYTE)hModule;
	//2.获取NT头
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
	//3.获取导出表的结构体指针
	PIMAGE_DATA_DIRECTORY pExportDir =
		&(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

	PIMAGE_EXPORT_DIRECTORY pExport =
		(PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + pExportDir->VirtualAddress);

	//EAT
	PDWORD pEAT = (PDWORD)((DWORD)hModule + pExport->AddressOfFunctions);
	//ENT
	PDWORD pENT = (PDWORD)((DWORD)hModule + pExport->AddressOfNames);
	//EIT
	PWORD pEIT = (PWORD)((DWORD)hModule + pExport->AddressOfNameOrdinals);

	//4.遍历导出表，获取GetProcAddress()函数地址
	DWORD dwNumofFun = pExport->NumberOfFunctions;
	DWORD dwNumofName = pExport->NumberOfNames;
	for (DWORD i = 0; i < dwNumofFun; i++)
	{
		//如果为无效函数，跳过
		if (pEAT[i] == NULL)
			continue;
		//判断是以函数名导出还是以序号导出
		DWORD j = 0;
		for (; j < dwNumofName; j++)
		{
			if (i == pEIT[j])
			{
				break;
			}
		}

		

		if (j != dwNumofName)
		{
			//如果是函数名方式导出的
			//函数名
			char* ExpFunName = (CHAR*)((PBYTE)hModule + pENT[j]);
			//进行对比,如果正确返回地址
			if (!strcmp(ExpFunName, "GetProcAddress"))
			{
				return pEAT[i] + pNtHeader->OptionalHeader.ImageBase;
			}
		}
		else
		{
			//序号
		}
	}
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	初始化宿主程序的TLS处理函数
//////////////////////////////////////////////////////////////////////////

VOID	InitiTLS(PIMAGE_TLS_DIRECTORY pTlsDirOfFile, PIMAGE_TLS_DIRECTORY pTlsDirOfShell)
{
	PIMAGE_TLS_CALLBACK* pTlsCallBack		= (PIMAGE_TLS_CALLBACK *)pTlsDirOfFile->AddressOfCallBacks;
	PIMAGE_TLS_CALLBACK* pTlsShellCallBack	= (PIMAGE_TLS_CALLBACK*)pTlsDirOfShell->AddressOfCallBacks;


	if (pTlsCallBack && pTlsShellCallBack)
	{
		while (*pTlsCallBack)
		{
			(*pTlsCallBack)((PVOID)g_dwImageBase, DLL_PROCESS_ATTACH, 0);
			*pTlsShellCallBack = *pTlsCallBack;
			pTlsCallBack++;
			pTlsShellCallBack++;
		}
	}





}


//////////////////////////////////////////////////////////////////////////
//	由于某些系统DLL库的FirstThunk指向的内容不是真实的，所以要进行判断
//	如果其中IAT所有的AddressOfData只要其中一个大于该dll在内存中的末地址
//	则视为错误，转而从OrignalFirstThunk来加载相应函数
//	参数：
//	HMODULE hMod			模块基地址
//////////////////////////////////////////////////////////////////////////

BOOL	CheckOutFirstThunk(HMODULE hMod, PIMAGE_IMPORT_DESCRIPTOR	pIAT)
{
	PIMAGE_DOS_HEADER			pDosHeader	= (PIMAGE_DOS_HEADER)hMod;
	PIMAGE_NT_HEADERS			pNtHeader	= (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD)hMod);
	PIMAGE_THUNK_DATA			pThunk		= (PIMAGE_THUNK_DATA)(pIAT->FirstThunk + g_dwImageBase);
	DWORD						dwImageEndVA;	//该DLL在内存中的末地址


	dwImageEndVA = pNtHeader->OptionalHeader.SizeOfImage + (DWORD)hMod;

	while (pThunk->u1.AddressOfData)
	{
		if (pThunk->u1.AddressOfData + (DWORD)hMod > dwImageEndVA)	return	FALSE;
		pThunk++;
	}
	return	TRUE;

}




//////////////////////////////////////////////////////////////////////////
//	解压数据的接口
//	参数：
//	LPBYTE		pPackedData		压缩数据的缓冲区
//	DWORD		dwPackedSize	压缩数据的大小
//	PDWORD		dwUnpackSize	[out]原始数据的大小
//	返回值：					解压数据的指针
//////////////////////////////////////////////////////////////////////////

LPBYTE	UnpackDataOfAplib(LPBYTE pPackedData, DWORD dwPackedSize, PDWORD	dwUnpackSize)
{
	DWORD	dwOrigSize;
	dwOrigSize = aPsafe_get_orig_size(pPackedData);

	DWORD	dwUnPackedSize;
	LPBYTE	pNewStr = (LPBYTE)g_pfnVirtualAlloc(NULL, dwOrigSize + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	MyZeroMemory(pNewStr, dwOrigSize + 1);

	dwUnPackedSize = aPsafe_depack(pPackedData, dwPackedSize, pNewStr, dwOrigSize);

	*dwUnpackSize = dwOrigSize + 1;

	if (dwUnPackedSize == APLIB_ERROR) 
	{
		g_pfnVirtualFree(pNewStr, 0, MEM_RELEASE);
		return NULL; 
	}

	return	pNewStr;
	
}


//////////////////////////////////////////////////////////////////////////
//	将区段解压，但不还原节表
//////////////////////////////////////////////////////////////////////////

VOID	DeComPress()
{
	//1. 提取压缩结构
	DWORD			dwCompressRva = g_stcShellData.dwCompressInfoRva;
	PComPressInfo	pSecComPressInfo	= (PComPressInfo)(g_dwImageBase + dwCompressRva);
	DWORD			dwNumOfSections		= g_stcShellData.dwNumOfSections;
	DWORD			dwOriginalSize;


	//2. 逐个解压，放入相应位置
	for (DWORD dwIndex = 0; dwIndex  < dwNumOfSections; dwIndex++)
	{

		if(g_stcShellData.stcConfig.dwCompressionType == COMPRESS_APLIB)
		pSecComPressInfo[dwIndex].pData = UnpackDataOfAplib((LPBYTE)(g_dwImageBase + pSecComPressInfo[dwIndex].CompressRva),
			pSecComPressInfo[dwIndex].CompressSize,
			&dwOriginalSize);
		
		if (g_stcShellData.stcConfig.dwCompressionType == COMPRESS_JCALG1_FAST)
			pSecComPressInfo[dwIndex].pData = UnpackDataOfJCALG1((LPBYTE)(g_dwImageBase + pSecComPressInfo[dwIndex].CompressRva),
				pSecComPressInfo[dwIndex].CompressSize,
				&dwOriginalSize,
				COMPRESS_JCALG1_FAST);

		if (g_stcShellData.stcConfig.dwCompressionType == COMPRESS_JCALG1_SMALL)
			pSecComPressInfo[dwIndex].pData = UnpackDataOfJCALG1((LPBYTE)(g_dwImageBase + pSecComPressInfo[dwIndex].CompressRva),
				pSecComPressInfo[dwIndex].CompressSize,
				&dwOriginalSize,
				COMPRESS_JCALG1_SMALL);
		

		MyCopyMemory((LPBYTE)(g_dwImageBase + pSecComPressInfo[dwIndex].OriginalRva),
			pSecComPressInfo[dwIndex].pData,
			dwOriginalSize);
	}
}


//////////////////////////////////////////////////////////////////////////
//	修复转储后的IAT
//////////////////////////////////////////////////////////////////////////

BOOL	RECTNewIAT()
{
	LPBYTE					pNewIAT = (LPBYTE)(g_stcShellData.dwNewIATRva + g_dwImageBase);
	DWORD					dwOldProtect;
	PIMAGE_THUNK_DATA		pThunk;
	CHAR*					szDllName;
	CHAR*					szFunName;
	DWORD					dwDllSize;
	DWORD					dwFunSize;
	DWORD					dwFunNum;
	DWORD					dwFunOrder;
	DWORD					dwFunAddr;
	HMODULE					hMod;
	BOOL					bRedirect = g_stcShellData.stcConfig.bIsApiRedirect;

	g_pfnVirtualProtect((LPVOID)(g_stcShellData.dwIATSectionBase + g_dwImageBase),
		g_stcShellData.dwIATSectionSize,
		PAGE_EXECUTE_READWRITE, &dwOldProtect);
	

	while ( *(PDWORD)pNewIAT )
	{
		pThunk = (PIMAGE_THUNK_DATA)(g_dwImageBase + *(PDWORD)pNewIAT);

		pNewIAT += sizeof(DWORD);

		dwDllSize = (DWORD)(*pNewIAT);

		pNewIAT++;

		szDllName = (CHAR*)g_pfnVirtualAlloc(NULL, dwDllSize + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		MyCopyMemory(szDllName, pNewIAT, dwDllSize + 1);

		hMod = g_pfnLoadLibraryA(szDllName);

		if (!hMod)
		{
			g_pfnVirtualFree(szDllName, 0, MEM_RELEASE);
			return FALSE;
		}

		pNewIAT += dwDllSize + 1;

		dwFunNum = *(PDWORD)pNewIAT;

		pNewIAT += sizeof(DWORD);

		while (dwFunNum)
		{
			
			dwFunSize = *pNewIAT;
			pNewIAT += sizeof(BYTE);

			if (!dwFunSize)
			{//序号
				dwFunOrder = *(PDWORD)pNewIAT;
				pNewIAT += sizeof(DWORD);
				dwFunAddr =  g_pfnGetProcAddress(hMod, (CHAR*)dwFunOrder);
				if (bRedirect)
					*(PDWORD)pThunk = (DWORD)RedirectIAT(szDllName, dwFunAddr);
				else
					*(PDWORD)pThunk = dwFunAddr;
			}
			else
			{//字符串
				szFunName = (CHAR*)g_pfnVirtualAlloc(NULL, dwFunSize + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				MyCopyMemory(szFunName, pNewIAT, dwFunSize + 1);
				pNewIAT += dwFunSize + 1;	
				dwFunAddr = g_pfnGetProcAddress(hMod, szFunName);
				if (bRedirect)
					*(PDWORD)pThunk = (DWORD)RedirectIAT(szDllName, dwFunAddr);
				else
					*(PDWORD)pThunk = dwFunAddr;
				g_pfnVirtualFree(szFunName, 0, MEM_RELEASE);
			}
			
			dwFunNum--;
			pThunk++;
		}

		g_pfnVirtualFree(szDllName, 0, MEM_RELEASE);

	}


	g_pfnVirtualProtect((LPVOID)(g_stcShellData.dwIATSectionBase + g_dwImageBase),
		g_stcShellData.dwIATSectionSize,
		dwOldProtect, &dwOldProtect);

	return TRUE;

}


//////////////////////////////////////////////////////////////////////////
//	提取转储后的重定位表，进行重定位修复
//////////////////////////////////////////////////////////////////////////

BOOL	RECNewReloc()
{
	LPBYTE	pData = (LPBYTE)(g_dwImageBase + g_stcShellData.dwNewRelocRva);
	DWORD	dwFirstRVA;
	DWORD	dwProtectRVA;
	DWORD	dwItemAddressOfReloc;
	DWORD	dwOldProtect;

	if (!g_stcShellData.dwNewRelocRva)
	{
		return FALSE;
	}



	while (*(PWORD)pData)
	{//遍历每一页

		if (*pData == IMAGE_REL_BASED_HIGHLOW)
		{
			pData++;

			dwFirstRVA = *(PDWORD)pData;
			//默认对齐粒度为0x1000，否则直接按照dwFirstRVA会影响到下一页，甚至下一段的属性，之前出现过bug
			dwProtectRVA = dwFirstRVA & 0xfffff000;	
		
			pData += sizeof(DWORD);

			//处理第一个重定位项,要加上virtualprotect改变页属性
			//注意每一页的属性都要改变
			g_pfnVirtualProtect((LPVOID)(dwProtectRVA + g_dwImageBase),
				0x2000,
				PAGE_EXECUTE_READWRITE, &dwOldProtect);

			dwItemAddressOfReloc = *(PDWORD)(g_dwImageBase + dwFirstRVA);

			dwItemAddressOfReloc = dwItemAddressOfReloc - g_stcShellData.dwImageBase + g_dwImageBase;

			*(PDWORD)(g_dwImageBase + dwFirstRVA) = dwItemAddressOfReloc;

			while (*(PWORD)pData)
			{//处理余项

				dwFirstRVA += (*(PWORD)pData);

				dwItemAddressOfReloc = *(PDWORD)(g_dwImageBase + dwFirstRVA);

				dwItemAddressOfReloc = dwItemAddressOfReloc - g_stcShellData.dwImageBase + g_dwImageBase;

				*(PDWORD)(g_dwImageBase + dwFirstRVA) = dwItemAddressOfReloc;

				pData += sizeof(WORD);

			}//while

			pData += sizeof(WORD);
		}//if

		g_pfnVirtualProtect((LPVOID)(dwProtectRVA + g_dwImageBase),
			0x2000,
			dwOldProtect, &dwOldProtect);

	}//while


	g_pfnVirtualProtect((LPVOID)(g_stcShellData.dwCodeBase + g_dwImageBase),
		g_stcShellData.dwCodeSize,
		dwOldProtect, &dwOldProtect);

	return TRUE;
}


//////////////////////////////////////////////////////////////////////////
//	对数据进行解压，压缩库为JCALG1
//	参数：
//	LPBYTE				pPackedData			压缩数据的缓冲区
//	DWORD				dwPackedSize		压缩数据的大小
//	PDWORD				dwUnpackSize		[out]解压后的原数据大小
//	DWORD				dwType				解压模式
//	dwType == 1			使用JCALG1_Decompress_Fast，快速解压，但是不包含校验
//	dwType == 0			使用JCALG1_Decompress_Small 慢速解压，包含校验
//	返回值：			解压数据的缓冲区
//////////////////////////////////////////////////////////////////////////

LPBYTE	UnpackDataOfJCALG1(LPBYTE pPackedData, DWORD dwPackedSize, PDWORD	dwUnpackSize, DWORD dwType)
{
	DWORD	dwBuffsize = JCALG1_GetUncompressedSizeOfCompressedBlock((void *)pPackedData);
	DWORD	dwExpandedSize;

	LPBYTE pUnpackedData;
	pUnpackedData = (LPBYTE)g_pfnVirtualAlloc(NULL,dwBuffsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	MyZeroMemory(pUnpackedData, dwBuffsize);

	if(dwType == COMPRESS_JCALG1_FAST)
	dwExpandedSize = JCALG1_Decompress_Fast((void *)pPackedData, (void *)pUnpackedData);
	else
	dwExpandedSize = JCALG1_Decompress_Small((void *)pPackedData, (void *)pUnpackedData);


	if (!dwExpandedSize)
	{
		g_pfnVirtualFree(pUnpackedData, 0, MEM_RELEASE);
		return NULL;
	}

	*dwUnpackSize = dwExpandedSize;
	return pUnpackedData;
}

//////////////////////////////////////////////////////////////////////////
//	对其IAT的API进行重定向
//	参数：
//	CHAR*			szDllName		该API对应Dll的名字
//	DWORD			dwFunAddr		API的真实地址
//	返回值：						重定向代码空间的起始地址
//////////////////////////////////////////////////////////////////////////

LPBYTE RedirectIAT(CHAR* szDllName, DWORD dwFunAddr)
{
	// 申请虚拟内存
	LPBYTE pVirBuf = (LPBYTE)g_pfnVirtualAlloc(NULL, 0x7, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pVirBuf)
	{
		return NULL;
	}

	if ((!strcmp(szDllName, "kernel32.dll"))
		|| (!strcmp(szDllName, "USER32.dll"))
		|| (!strcmp(szDllName, "advapi32.dll"))
		|| (!strcmp(szDllName, "gdi32.dll")))
	{

		// 赋值机器码
		// mov ebx,address ;jmp ebx
		pVirBuf[0] = 0xBB;
		*(DWORD*)(pVirBuf + 1) = dwFunAddr;
		pVirBuf[5] = 0xFF;
		pVirBuf[6] = 0xE3;
		return pVirBuf;
	}

	g_pfnVirtualFree(pVirBuf, 0, MEM_RELEASE);

	return (LPBYTE)dwFunAddr;

}

//////////////////////////////////////////////////////////////////////////
//	修改PEB结构中的某些字段，使类似LordPE这种软件不能成功dump宿主程序
//////////////////////////////////////////////////////////////////////////

VOID AntiDump()
{
	PPEB pPeb;

	_asm
	{
		mov eax, fs:[0x30];					//获得PEB地址
		mov pPeb, eax;
	}

	PMYPEB_LDR_DATA					pldrdata		=	(PMYPEB_LDR_DATA)pPeb->Ldr;
	PMYLDR_DATA_TABLE_ENTRY			pLoadDataEntry	=	(PMYLDR_DATA_TABLE_ENTRY)pldrdata->InLoadOrderModuleList.Flink;
	PMYLDR_DATA_TABLE_ENTRY			pMemDataEntry	=	(PMYLDR_DATA_TABLE_ENTRY)pldrdata->InMemoryOrderModuleList.Flink;
	PMYRTL_USER_PROCESS_PARAMETERS	pRtl			=	(PMYRTL_USER_PROCESS_PARAMETERS)pPeb->ProcessParameters;

	//此项不可抹去，不然会产生异常
	//if (!CleanUnicodeString(&pLoadDataEntry->FullDllName))	return;

	if (!CleanUnicodeString(&pLoadDataEntry->BaseDllName))	return;
	if (!CleanUnicodeString(&pMemDataEntry->BaseDllName))	return;
	if (!CleanUnicodeString(&pMemDataEntry->FullDllName))	return;

	if (!CleanUnicodeString(&pRtl->CommandLine))	return;
	if (!CleanUnicodeString(&pRtl->ImagePathName))	return;
	if (!CleanUnicodeString(&pRtl->WindowTitle))	return;

	pLoadDataEntry->SizeOfImage = 0x1000;

}


//////////////////////////////////////////////////////////////////////////
//	配合AntiDump使用，清楚Unicode类型的字符数组
//////////////////////////////////////////////////////////////////////////

BOOL	CleanUnicodeString(PUNICODE_STRING pUnicodeString)
{
	if (!pUnicodeString)
	{
		return FALSE;
	}
	pUnicodeString->Buffer			= NULL;
	pUnicodeString->Length			= 0;
	pUnicodeString->MaximumLength	= 0;

	return TRUE;
}



//////////////////////////////////////////////////////////////////////////
//	反调试功能，通过FS->TEB->PEB->IsDebugging来判断，比调用API和从FS->PEB获取更好
//////////////////////////////////////////////////////////////////////////


VOID	AntiDebugging()
{
	BOOL bIsDebugging;

	__asm
	{
		mov		eax,dword ptr fs:[018h]
		mov		eax,dword ptr [eax + 030h]
		movzx	eax,byte ptr [eax + 02h]
		mov		bIsDebugging, eax
	}


	if (bIsDebugging)	g_pfnExitProcess(0x1);

}


//////////////////////////////////////////////////////////////////////////
//	对文件进行校验，使用CRC32算法
//	过程：
//	返回值：TRUE代表验证通过，反之
//////////////////////////////////////////////////////////////////////////

BOOL	FileVerification()
{
	HMODULE					hMod;
	CHAR*					szFileName;
	HANDLE					hFile;
	DWORD					dwSize;
	DWORD					dwBytesOfRead;
	LPBYTE					pBuff		= NULL;
	PIMAGE_DOS_HEADER		pDosHeader	= NULL;
	PIMAGE_NT_HEADERS		pNtHeader	= NULL;
	DWORD					dwCRC32;


	szFileName = (CHAR*)g_pfnVirtualAlloc(NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);

	MyZeroMemory(szFileName, MAX_PATH);


	//1. 获取模块句柄
	
	//判断是否为DLL
	if (g_stcShellData.bDll)
		hMod = g_pfnGetModuleHandleA(g_stcShellData.szDllName);
	else
		hMod = g_pfnGetModuleHandleA(NULL);


	//2. 获取exe或dll的绝对路径
	g_pfnGetModuleFileNameA(hMod, szFileName, MAX_PATH*sizeof(CHAR));


	//3.获取文件长度，读取DOS头和PE头
	hFile = g_pfnCreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
		NULL);

	dwSize = g_pfnGetFileSize(hFile, NULL);

	if (dwSize == INVALID_FILE_SIZE)		return FALSE;

	pBuff = (LPBYTE)g_pfnVirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (pBuff == NULL)	return FALSE;

	g_pfnReadFile(hFile, pBuff, dwSize, &dwBytesOfRead, NULL);

	pDosHeader	= (PIMAGE_DOS_HEADER)pBuff;

	pNtHeader	= (PIMAGE_NT_HEADERS)(pBuff + pDosHeader->e_lfanew);

	dwCRC32 = CalcuCRC((UCHAR*)pNtHeader, dwSize - pDosHeader->e_lfanew);

	g_pfnCloseHandle(hFile);

	if (dwCRC32 == *(PDWORD)((DWORD)pNtHeader - 4))
	{
		g_pfnVirtualFree(szFileName, 0, MEM_RELEASE);
		g_pfnVirtualFree(pBuff, 0, MEM_RELEASE);
		return TRUE;
	}

	g_pfnVirtualFree(szFileName, 0, MEM_RELEASE);
	g_pfnVirtualFree(pBuff, 0, MEM_RELEASE);	
	return	FALSE;

}









//////////////////////////////////////////////////////////////////////////
//	对内存中的代码段进行校验，代码段的大小通过内存粒度对齐过
//	返回值：验证通过返回TRUE
//////////////////////////////////////////////////////////////////////////

BOOL	CodeMemVerification()
{
	DWORD	dwCodeBase;
	DWORD	dwCodeSize;
	DWORD	dwCRC32;
	

	dwCodeBase = g_stcShellData.dwCodeBase;
	dwCodeSize = g_stcShellData.dwCodeSize;

	dwCRC32 = CalcuCRC( (UCHAR*) (g_dwImageBase + dwCodeBase), dwCodeSize);

	//如果有重定位修复，则不进行验证，因为修复全局变量会改变代码段，所以CRC32的计算会出错
	if(g_stcShellData.stcPERelocDir.VirtualAddress == 0)
//	if(g_stcShellData.stcIATDir.VirtualAddress == 0)
	if (dwCRC32 != g_stcShellData.dwCodeMemCRC32)	return FALSE;

	return TRUE;

}


//////////////////////////////////////////////////////////////////////////
//	扫描内存中是否指定的特征串
//	例如OD特征串有OllyDbg和OllyDBG
//	利用了VirtualQuery 和 KMP匹配算法
//	参数：
//	char*		Charac	- 特征串指针
//	int			Length	- 特征串大小
//	返回值：匹配则TRUE
//	注：该操作会耗费大量的CPU时间，在考虑性能上时要慎用
//////////////////////////////////////////////////////////////////////////

BOOL	SeachCharac(char* Charac, int Length)
{
	MEMORY_BASIC_INFORMATION	stcMbi;
	SYSTEM_INFO					stcSi;
	DWORD						dwPageAddr;
	DWORD						dwMinPageAddr;			//用户空间最小地址
	DWORD						dwMaxPageAddr;			//用户空间最高地址
	int *	prefix = (int *)g_pfnVirtualAlloc(NULL, Length * sizeof(int), MEM_COMMIT, PAGE_READWRITE);
	
	if (prefix == NULL) return FALSE;

	//1. 获取前缀
	g_pfnOutPutDebugString("//1. 获取前缀");
	kmpPrefixFunction(Charac, Length, prefix);

	g_pfnOutPutDebugString("g_pfnGetSystemInfo(&stcSi);");
	g_pfnGetSystemInfo(&stcSi);

	dwMinPageAddr = (DWORD)stcSi.lpMinimumApplicationAddress;
	dwMaxPageAddr = (DWORD)stcSi.lpMaximumApplicationAddress;
	dwPageAddr = dwMinPageAddr;

	//2. 遍历模块

	for (; dwPageAddr < dwMaxPageAddr; dwPageAddr += stcMbi.RegionSize)
	{
		g_pfnOutPutDebugString("VirtualQuery");
		g_pfnVirtualQuery((LPVOID)dwPageAddr, &stcMbi, sizeof(stcMbi));

		if (stcMbi.State != MEM_COMMIT || stcMbi.Protect & PAGE_GUARD)	continue;

		g_pfnOutPutDebugString("kmpMatch");
		if (kmpMatch((char*)dwPageAddr, stcMbi.RegionSize, Charac, Length, prefix))
		{
			g_pfnVirtualFree(prefix, 0, MEM_RELEASE);
			return TRUE;
		}

	}

	g_pfnOutPutDebugString("Failed To Scan");
	g_pfnVirtualFree(prefix, 0, MEM_RELEASE);
	return FALSE;
}



//混淆函数
void _stdcall FusedFunc(DWORD dwfuncAddress)
{
	_asm
	{
		jmp label1
		label2 :
		_emit 0xeb; //跳到下面的call
		_emit 0x04;
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x123402EB]; //执行EB 02  也就是跳到下一句

														  //	call Init;// 获取一些基本函数的地址

														  // call下一条,用于获得eip
		_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		//-------跳到下面的call
		_emit 0xEB;
		_emit 0x0E;

		//-------花
		PUSH 0x0;
		PUSH 0x0;
		MOV EAX, DWORD PTR FS : [0];
		PUSH EAX;
		//-------花


		// fused:
		//作用push下一条语句的地址
		//pop eax;
		//add eax, 0x1b;
		/*push eax;*/
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x5019C083];

		push dwfuncAddress; //这里如果是参数传入的需要注意上面的add eax,??的??
		retn;

		jmp label3

			// 花
			_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		// 花


	label1:
		jmp label2
			label3 :
	}
}
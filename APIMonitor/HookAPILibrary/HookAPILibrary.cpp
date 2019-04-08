// HookAPILibrary.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"

HANDLE					g_hPipe1		= NULL;
HANDLE					g_hPipe2		= NULL;
lpModInfo				g_lpModList		= NULL;
DWORD					g_dwModListLen	= LIST_INC;

DWORD					dwObjectModBaseStart;				//宿主程序基址
DWORD					dwObjectModBaseEnd;
DWORD					dwSelfModBaseStart;					//注入DLL基址
DWORD					dwSelfModBaseEnd;

DWORD					g_dwPrivateIndex = 0;		//AddModuleToList的私有全局变量,需要初始化为0
BOOL					IsHookCallAgain = FALSE;

extern DWORD			g_dwDefNUm;

extern DefFileInfo		g_stcDef[MAX_DEF_FILENAME_LENGTH];


StringFilteredDllList	g_szFilteredDllList[] = { { L"MFC",3 },{L"GDI32",5} , \
{L"gdi32full", 9 }, { L"ntdll",5 }, { L"win32u",6 }, { L"uxtheme",7 }, {L"VCRUNTIME" ,9  }, \
{L"ole32", 5}, {L"windows",7} };





StringFilteredDllList	g_szProcessingDlllist[] = { { L"KERNEL32", 8 }   /*{L"WS2_32",6},{L"KERNELBASE",10} , \
						{L"KERNEL32",8 }, {L"USER32",6} ,{L"IMM32",5} */ };


//////////////////////////////////////////////////////////////////////////
//	模拟指令处理线程接收指令数据
//	参数：
//	LPVOID lpPara	管道句柄
//////////////////////////////////////////////////////////////////////////

DWORD  WINAPI ThreadProc(LPVOID lpPara)
{
	HANDLE			hPipe = (HANDLE)lpPara;
	LPBYTE			pBuff = new BYTE[1024];
	DWORD			dwNumOfRead;
	DWORD			dwRet;
	lpPacketInfo	lpPacket;
	lpHookMod		lpHook;
	lpFilteredInfo	lpFilterd;


	ZeroMemory(pBuff, 1024);

	do
	{
		if (dwRet = ReadFile(hPipe, pBuff, 1024, &dwNumOfRead, NULL))
			//此处设置一个消息分类器，用以分析监控端发送而来的消息
		{
			
			lpPacket = (lpPacketInfo)pBuff;
			//分类器

			switch (lpPacket->dwType)
			{
			case HOOK_MSG:

				lpHook = (lpHookMod)lpPacket->Data;
				if (lpHook->bHook)
				{//对指定模块进行Hook
					OutputDebugString(L"指定模块即将被Hook");
					if (g_lpModList[lpHook->dwModIndex].bActive == FALSE)
					{
						HookModule(lpHook->dwModIndex);
					}
					else
					{
						ReHookModule(lpHook->dwModIndex);
					}
					OutputDebugString(L"指定模块被Hook");
				}
				else
				{//对指定模块进行UnHook
					OutputDebugString(L"指定模块即将被UnHook");
					UnHookModule(lpHook->dwModIndex);
					OutputDebugString(L"指定模块被UnHook");
				}


				break;

			case FILTER_MSG:
				lpFilterd = (lpFilteredInfo)lpPacket->Data;

				if (lpFilterd->bFilterd)
				{//过滤
					g_lpModList[lpFilterd->dwModIndex].lpApiList[lpFilterd->dwApiIndex].bIsFiltered = TRUE;
				}
				else
				{//不过滤
					g_lpModList[lpFilterd->dwModIndex].lpApiList[lpFilterd->dwApiIndex].bIsFiltered = FALSE;
				}

				break;


			default:
				break;
			}

			
		

		}

	}while (dwRet);

	CloseHandle(hPipe);
	delete[] pBuff;
	return 0;
}


//////////////////////////////////////////////////////////////////////////
//	模拟主线程发送API采集到的相关数据
//	参数：
//	LPVOID lpPara	管道句柄
//////////////////////////////////////////////////////////////////////////

DWORD  WINAPI ThreadProc2(LPVOID lpPara)
{
	HANDLE	hPipe = (HANDLE)lpPara;
	DWORD	dwPorcessID;
	DWORD	dwNumOfWritten;
	WCHAR	szNamePipe[1024] = { 0 };

	OutputDebugString(L"[DLL端]获取进程ID");
	dwPorcessID = GetCurrentProcessId();

	OutputDebugString(L"[DLL端]负责管道1的主线程已经开启");

	for (DWORD dwIndex = 0; dwIndex < 20; dwIndex++)
	{
		wsprintf(szNamePipe, L"%s_ID:%d_Index:%d", L"[DLL]指令，发送采集的到API数据", dwPorcessID, dwIndex);
		WriteFile(hPipe, szNamePipe, sizeof(WCHAR)*(wcslen(szNamePipe) + 1), &dwNumOfWritten, NULL);
	}

	CloseHandle(hPipe);

	return 0;
}


//////////////////////////////////////////////////////////////////////////
//	连接管道，返回句柄
//	参数：
//	WCHAR* szNamePipe	管道的名称
//	返回值：			管道句柄,否则为NULL
//////////////////////////////////////////////////////////////////////////

HANDLE ConnectToNamePipe(WCHAR* szNamePipe)
{
	HANDLE  hPipe;
	DWORD	dwConnectCounter = 50;//50次的连接尝试

	while(WaitNamedPipe(szNamePipe, NMPWAIT_WAIT_FOREVER) == FALSE)
	{
		Sleep(200);
		dwConnectCounter--;

		if (dwConnectCounter == 0)
			return NULL;
	}

	hPipe = CreateFile(szNamePipe, GENERIC_READ | GENERIC_WRITE, 0,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	return hPipe;
}


//////////////////////////////////////////////////////////////////////////
//	扫描内存中的模块，并且添加到Modlist当中，然后在进一步扫描其Api
//	添加Api后，进行Hook操作，在该过程中会将相关数据发送至监控端
//////////////////////////////////////////////////////////////////////////

BOOL	ScanModule()
{
	//扫描内存中的模块
	//使用GetSystemInfo和VirtualQuery
	DWORD						dwPageAddr;				
	DWORD						dwMinPageAddr;			//用户空间最小地址
	DWORD						dwMaxPageAddr;			//用户空间最高地址
	MEMORY_BASIC_INFORMATION	stcMbi;
	MEMORY_BASIC_INFORMATION	stcMibOfApi;
	SYSTEM_INFO					stcSi;
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeader;
	PIMAGE_EXPORT_DIRECTORY		pExp;
	WCHAR						szDllName[MAX_NAME_LEN];
	DWORD						dwWideCharSize;
	DWORD						dwCurModIndex;			//当前ModIndex
	DWORD						dwCurApiIndex;			//当前ApiIndex
	DWORD						dwCurModBaseAddr;		//当前模块的起始地址
	DWORD						dwCurModBaseEnd;		//当前模块的末地址
	PDWORD						dpExpAddrOfFunc;
	PDWORD						dpExpAddrOfName;
	PWORD						wpExpAddrOfNameOri;

	lpApiInfo					lpCurApiList;
	ShellCode					stcShellCode;

	HANDLE						hSnapShot;
	THREADENTRY32				stcThreadInfo;
	BOOL						bIgnoringHook;
	WCHAR						szTest[MAX_NAME_LEN] = { 0 };
	DWORD						dwNewAddr;
	DWORD						dwObjectBaseAddr;
	WCHAR						szProgramName[MAX_PATH] = { 0 };
	BOOL						bIgnored = TRUE;
	//////////////////////////////////////////////////////////////////////////
	// 1.1 添加detour对当前所有线程的刷新，过滤那些小字节的函数
	//////////////////////////////////////////////////////////////////////////
	OutputDebugString(L"1.1 添加detour对当前所有线程的刷新，过滤那些小字节的函数");
	DetourTransactionBegin();
	DetourSetIgnoreTooSmall(TRUE);
	
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

	if (hSnapShot != INVALID_HANDLE_VALUE)
	{
		if (Thread32First(hSnapShot, &stcThreadInfo))
		{
			DetourUpdateThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, stcThreadInfo.th32ThreadID));
			while (Thread32Next(hSnapShot, &stcThreadInfo))
			{
				DetourUpdateThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, stcThreadInfo.th32ThreadID));
			}
		}
	}
	
	//1.2 获取系统信息，得到用户空间的范围，用于遍历模块
	OutputDebugString(L"1.2 获取系统信息，得到用户空间的范围，用于遍历模块");

	GetSystemInfo(&stcSi);

	dwMinPageAddr	= (DWORD)stcSi.lpMinimumApplicationAddress;
	dwMaxPageAddr	= (DWORD)stcSi.lpMaximumApplicationAddress;
	dwPageAddr		= dwMinPageAddr;
	

	//1.3 获取宿主程序的模块信息并添加到列表，但是不会在监控端显示
	dwObjectBaseAddr = (DWORD)GetModuleHandle(NULL);

	GetModuleFileName((HMODULE)dwObjectBaseAddr, szProgramName, MAX_PATH);

	pDosHeader = (PIMAGE_DOS_HEADER)dwObjectBaseAddr;

	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + dwObjectBaseAddr);


	dwCurModIndex = AddModuleToList(dwObjectBaseAddr, pNtHeader->OptionalHeader.SizeOfImage, PathFindFileName(szProgramName));

	SendModInfo(&g_lpModList[dwCurModIndex]);



	//2. 遍历模块
	for (; dwPageAddr < dwMaxPageAddr; dwPageAddr += stcMbi.RegionSize)
	{
		bIgnored = TRUE;

		VirtualQuery( (LPVOID)dwPageAddr, &stcMbi, sizeof(stcMbi));

		if (stcMbi.State != MEM_COMMIT || stcMbi.Protect & PAGE_GUARD)	continue;
	
		pDosHeader = (PIMAGE_DOS_HEADER)dwPageAddr;

		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)	continue;
	
		pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + dwPageAddr);

		if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)	continue;
	
		if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)	continue;
	
		pExp = (PIMAGE_EXPORT_DIRECTORY)(dwPageAddr + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		
		//如果遍历到注入DLL，则跳过
		if(dwPageAddr == dwSelfModBaseStart)	continue;

		ZeroMemory(szDllName, sizeof(WCHAR)*MAX_NAME_LEN);
		if (pExp->Name)
		{//若该模块做过特殊处理，则利用GetModuleFileName来获取模块名字
			
			dwWideCharSize = MultiByteToWideChar(CP_ACP, NULL, (CHAR*)(dwPageAddr + pExp->Name), strlen((CHAR*)(dwPageAddr + pExp->Name)),
				NULL, NULL);

			MultiByteToWideChar(CP_ACP, NULL, (CHAR*)(dwPageAddr + pExp->Name),
				strlen((CHAR*)(dwPageAddr + pExp->Name)),
				szDllName, dwWideCharSize);

			OutputDebugString(L"若该模块做过特殊处理，则利用GetModuleFileName来获取模块名字");
		}
		else
		{
			//此处的处理主要是针对Wow64系列的DLL，他们的名称不能用该API获取,直接跳到下一个模块
			if(GetModuleFileName((HMODULE)dwPageAddr, szDllName, MAX_NAME_LEN) == 0)
				continue;	
		}


		OutputDebugString(szDllName);

		OutputDebugString(L"2.1 添加模块信息");
		//2.1 添加模块信息
		dwCurModIndex	= AddModuleToList(dwPageAddr, pNtHeader->OptionalHeader.SizeOfImage, szDllName);
		dpExpAddrOfFunc = (PDWORD)(pExp->AddressOfFunctions + dwPageAddr);
		dpExpAddrOfName = (PDWORD)(pExp->AddressOfNames + dwPageAddr);
		wpExpAddrOfNameOri = (PWORD)(pExp->AddressOfNameOrdinals + dwPageAddr);
		g_lpModList[dwCurModIndex].dwApiListLen = pExp->NumberOfNames;

		// 当前模块的范围
		dwCurModBaseAddr	= dwPageAddr;
		dwCurModBaseEnd		= dwPageAddr + pNtHeader->OptionalHeader.SizeOfImage;


		//2.3 初始化Shellcode
		OutputDebugString(L"2.3 初始化Shellcode");
		InitApiShellStruct(&stcShellCode);

		//2.4 发送Mod相关信息至监控端
		OutputDebugString(L"2.4 发送Mod相关信息至监控端");

		SendModInfo(&g_lpModList[dwCurModIndex]);

		OutputDebugString(L"2.5 遍历模块的Api，添加API信息,只处理按字符串导出的Api");
	
		
		//for (DWORD i = 0; i < _countof(g_szProcessingDlllist); i++)
		//{
		//	if (_wcsnicmp(szDllName,
		//		g_szProcessingDlllist[i].szDllName,
		//		g_szProcessingDlllist[i].dwCheckSize) == 0)
		//	{
		//		bIgnored = FALSE;
		//		break;
		//	}
		//}


		//if (bIgnored)	continue;


		//2.5 遍历模块的Api，添加API信息,只处理按字符串导出的Api
		for (DWORD	dwIndex = 0; dwIndex < pExp->NumberOfNames ; dwIndex++)
		{
			//预处理,默认不能Hook
		//	bIgnoringHook = TRUE;

			//地址是否在模块外，不知道有没有这种情况发生
			if( (dpExpAddrOfFunc[wpExpAddrOfNameOri[dwIndex]]  + dwPageAddr) >= dwCurModBaseEnd ||
			(dpExpAddrOfFunc[wpExpAddrOfNameOri[dwIndex]]+ dwPageAddr) <= dwCurModBaseAddr)
				continue;

			VirtualQuery( (LPVOID)(dpExpAddrOfFunc[wpExpAddrOfNameOri[dwIndex]] + dwPageAddr),
					&stcMibOfApi,
					sizeof(MEMORY_BASIC_INFORMATION));
			
			//该Api是否可执行
			//	0xF0的意思，查看MSDN文档，只要是带有执行属性，都会在高4位设位
			//	只要让其属性&0xF0后只要为1，就可以说明该区域可以执行
			if( ((stcMibOfApi.AllocationProtect & 0xF0) == 0)   ||   stcMibOfApi.State != MEM_COMMIT)
				continue;
			

			//做完上述预处理后在申请节点
			dwCurApiIndex =  AllocApiFromList(&g_lpModList[dwCurModIndex]);

			if(dwCurApiIndex == -1) continue;

			lpCurApiList = g_lpModList[dwCurModIndex].lpApiList;

			lpCurApiList[dwCurApiIndex].bIsHooked		= FALSE;			//默认Api不过滤
			lpCurApiList[dwCurApiIndex].dwOridinal		= wpExpAddrOfNameOri[dwIndex];
			lpCurApiList[dwCurApiIndex].dwModIndex		= dwCurModIndex;
			lpCurApiList[dwCurApiIndex].dwApiIndex		= dwCurApiIndex;
			lpCurApiList[dwCurApiIndex].dwApiRealAddr	= dpExpAddrOfFunc[wpExpAddrOfNameOri[dwIndex]] + dwPageAddr;
			
			dwWideCharSize = MultiByteToWideChar(CP_ACP, NULL, (CHAR*)(dwPageAddr + dpExpAddrOfName[dwIndex]), strlen((CHAR*)(dwPageAddr + dpExpAddrOfName[dwIndex])),
				NULL, NULL);

			MultiByteToWideChar(CP_ACP, NULL, (CHAR*)(dwPageAddr + dpExpAddrOfName[dwIndex]), 
				strlen((CHAR*)(dwPageAddr + dpExpAddrOfName[dwIndex])),
				lpCurApiList[dwCurApiIndex].szApiName, dwWideCharSize);

			lpCurApiList[dwCurApiIndex].lpShellBuf = (lpShellCode)VirtualAlloc(NULL, sizeof(ShellCode), 
				MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			stcShellCode.dwPushApiIndex = dwCurApiIndex;
			stcShellCode.dwPushModIndex = dwCurModIndex;
			
			DWORD	dwTrapAddr = (DWORD)GetProcAddress((HMODULE)dwSelfModBaseStart, "TrappedApiCall");

	
			stcShellCode.dwCallAddr = (DWORD)dwTrapAddr - ((DWORD)lpCurApiList[dwCurApiIndex].lpShellBuf + offsetof(ShellCode, dwCallAddr) + 4);
			stcShellCode.dwJmpApiAddr = lpCurApiList[dwCurApiIndex].dwApiRealAddr - ((DWORD)lpCurApiList[dwCurApiIndex].lpShellBuf + offsetof(ShellCode, dwJmpApiAddr) + 4);
			
			CopyMemory(lpCurApiList[dwCurApiIndex].lpShellBuf, &stcShellCode, sizeof(ShellCode));

			//2.6 发送Api相关信息(注：必须先发送在Hook，不然其Api真实地址会被Detour替换)
			SendApiInfo(&lpCurApiList[dwCurApiIndex]);

			

			//2.7 HOOK API，并且做一个过滤预处理，让过滤列表szFilteredDllList中的Dll不能被HOOK，保证宿主程序执行效率
			//for (DWORD i = 0; i < _countof(g_szProcessingDlllist); i++)
			//{
			//	if (_wcsnicmp(g_lpModList[dwCurModIndex].szModName,
			//		g_szProcessingDlllist[i].szDllName,
			//		g_szProcessingDlllist[i].dwCheckSize) == 0)
			//		bIgnoringHook = FALSE;
			//}


			bIgnoringHook = FilterApi(g_lpModList[dwCurModIndex].szModName, 
				lpCurApiList[dwCurApiIndex].szApiName);


			if (bIgnoringHook == FALSE )
			{		
					wsprintf(szTest, L"ApiName = %s",  lpCurApiList[dwCurApiIndex].szApiName);
					OutputDebugString(szTest);

					DetourAttachEx((PVOID*)&lpCurApiList[dwCurApiIndex].dwApiRealAddr,
					lpCurApiList[dwCurApiIndex].lpShellBuf,
					(PDETOUR_TRAMPOLINE*)&dwNewAddr, NULL, NULL);
					lpCurApiList[dwCurApiIndex].bIsHooked = TRUE;
					lpCurApiList[dwCurApiIndex].lpShellBuf->dwJmpApiAddr = dwNewAddr - ((DWORD)lpCurApiList[dwCurApiIndex].lpShellBuf + offsetof(ShellCode, dwJmpApiAddr) + 4);
			
			}
		
		}//for


	}//for


	SendFinish(FINISH_MODMSG);

	OutputDebugString(L"DetourTransactionCommit 前");
	DetourTransactionCommit();
	OutputDebugString(L"DetourTransactionCommit 后");


	return TRUE;
}





BOOL	ScanModule2()
{
	//扫描内存中的模块
	//使用GetSystemInfo和VirtualQuery
	DWORD						dwPageAddr;
	DWORD						dwMinPageAddr;			//用户空间最小地址
	DWORD						dwMaxPageAddr;			//用户空间最高地址
	MEMORY_BASIC_INFORMATION	stcMbi;
	SYSTEM_INFO					stcSi;
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeader;
	PIMAGE_EXPORT_DIRECTORY		pExp;
	WCHAR						szDllName[MAX_NAME_LEN];
	DWORD						dwWideCharSize;
	DWORD						dwCurModIndex;			//当前ModIndex
	PDWORD						dpExpAddrOfFunc;
	PDWORD						dpExpAddrOfName;
	PWORD						wpExpAddrOfNameOri;

	WCHAR						szTest[MAX_NAME_LEN] = { 0 };

	DWORD						dwObjectBaseAddr;
	WCHAR						szProgramName[MAX_PATH] = { 0 };


	//1.2 获取系统信息，得到用户空间的范围，用于遍历模块
	OutputDebugString(L"1.2 获取系统信息，得到用户空间的范围，用于遍历模块");

	GetSystemInfo(&stcSi);

	dwMinPageAddr = (DWORD)stcSi.lpMinimumApplicationAddress;
	dwMaxPageAddr = (DWORD)stcSi.lpMaximumApplicationAddress;
	dwPageAddr = dwMinPageAddr;

	
	//1.3 获取宿主程序的模块信息并添加到列表，但是不会在监控端显示
	dwObjectBaseAddr = (DWORD)GetModuleHandle(NULL);
	
	GetModuleFileName((HMODULE)dwObjectBaseAddr, szProgramName, MAX_PATH);

	pDosHeader = (PIMAGE_DOS_HEADER)dwObjectBaseAddr;

	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + dwObjectBaseAddr);


	dwCurModIndex = AddModuleToList(dwObjectBaseAddr, pNtHeader->OptionalHeader.SizeOfImage, PathFindFileName(szProgramName));

	SendModInfo(&g_lpModList[dwCurModIndex]);



	//2. 遍历模块
	for (; dwPageAddr < dwMaxPageAddr; dwPageAddr += stcMbi.RegionSize)
	{
		VirtualQuery((LPVOID)dwPageAddr, &stcMbi, sizeof(stcMbi));

		if (stcMbi.State != MEM_COMMIT || stcMbi.Protect & PAGE_GUARD)	continue;

		pDosHeader = (PIMAGE_DOS_HEADER)dwPageAddr;

		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)	continue;

		pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + dwPageAddr);

		if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)	continue;

		if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)	continue;

		pExp = (PIMAGE_EXPORT_DIRECTORY)(dwPageAddr + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		//如果遍历到注入DLL，则跳过
		if (dwPageAddr == dwSelfModBaseStart)	continue;

		ZeroMemory(szDllName, sizeof(WCHAR)*MAX_NAME_LEN);
		if (pExp->Name)
		{//若该模块做过特殊处理，则利用GetModuleFileName来获取模块名字

			dwWideCharSize = MultiByteToWideChar(CP_ACP, NULL, (CHAR*)(dwPageAddr + pExp->Name), strlen((CHAR*)(dwPageAddr + pExp->Name)),
				NULL, NULL);

			MultiByteToWideChar(CP_ACP, NULL, (CHAR*)(dwPageAddr + pExp->Name),
				strlen((CHAR*)(dwPageAddr + pExp->Name)),
				szDllName, dwWideCharSize);

			OutputDebugString(L"若该模块做过特殊处理，则利用GetModuleFileName来获取模块名字");
		}
		else
		{
			//此处的处理主要是针对Wow64系列的DLL，他们的名称不能用该API获取,直接跳到下一个模块
			if (GetModuleFileName((HMODULE)dwPageAddr, szDllName, MAX_NAME_LEN) == 0)
				continue;
		}

		OutputDebugString(szDllName);

		OutputDebugString(L"2.1 添加模块信息");
		//2.1 添加模块信息
		dwCurModIndex = AddModuleToList(dwPageAddr, pNtHeader->OptionalHeader.SizeOfImage, szDllName);
		dpExpAddrOfFunc = (PDWORD)(pExp->AddressOfFunctions + dwPageAddr);
		dpExpAddrOfName = (PDWORD)(pExp->AddressOfNames + dwPageAddr);
		wpExpAddrOfNameOri = (PWORD)(pExp->AddressOfNameOrdinals + dwPageAddr);
		g_lpModList[dwCurModIndex].dwApiListLen = pExp->NumberOfNames;

		//2.4 发送Mod相关信息至监控端
		OutputDebugString(L"2.4 发送Mod相关信息至监控端");

		SendModInfo(&g_lpModList[dwCurModIndex]);

	}//for


	SendFinish(FINISH_MODMSG);

	return TRUE;
}








//////////////////////////////////////////////////////////////////////////
//	添加当前模块信息至列表中，若列表空间已经使用完毕，则进行扩充
//	参数：
//	DWORD	dwBaseAddr	- 模块基址
//	DWORD	dwImageSize	- 模块大小
//	WCHAR*	szModName	- 模块名
//	注：	使用了g_dwPrivateIndex为该列表的全局索引变量,且第一个搜索到的模块做为的索引为1	\
//	索引为0的模块为自身模块信息
//	返回值:		成功则返回当前在列表中的索引，否则为-1
//////////////////////////////////////////////////////////////////////////

DWORD	AddModuleToList(DWORD dwBaseAddr, DWORD dwImageSize, WCHAR* szModName)
{
	
	

	//若空间不足， 扩展数组空间
	if (g_dwPrivateIndex >= g_dwModListLen)
	{
		lpModInfo	pTemp;
		//位置不够，要扩展数组长度
		pTemp = (lpModInfo)VirtualAlloc(NULL, sizeof(ModInfo) * (g_dwModListLen + LIST_INC), MEM_COMMIT, PAGE_READWRITE);
		
		if (pTemp == NULL)	return -1;
	
		CopyMemory(pTemp, g_lpModList, sizeof(ModInfo)* g_dwModListLen);
		g_dwModListLen += LIST_INC;
		VirtualFree(g_lpModList, 0, MEM_RELEASE);
		g_lpModList = pTemp;
	}
		
	g_lpModList[g_dwPrivateIndex].dwBaseAddr	= dwBaseAddr;
	g_lpModList[g_dwPrivateIndex].dwImageSize	= dwImageSize;
	g_lpModList[g_dwPrivateIndex].dwModIndex	= g_dwPrivateIndex;
	g_lpModList[g_dwPrivateIndex].bIsFiltered	= FALSE;
	g_lpModList[g_dwPrivateIndex].bActive		= FALSE;
	g_lpModList[g_dwPrivateIndex].lpApiList		= NULL;
	g_lpModList[g_dwPrivateIndex].dwPrivateApiListIndex = 0;
	
	wcscpy_s(g_lpModList[g_dwPrivateIndex].szModName, szModName);
	
	g_dwPrivateIndex++;


	return g_dwPrivateIndex-1;
}


//////////////////////////////////////////////////////////////////////////
//	申请Apilist中的一个节点，返回索引号便于操作
//	注：不可扩展数组，DetourAttach函数会保存之前未拓展的数组
//	参数：
//	lpModInfo	lpCurModNode - 指向当前模块节点
//	返回值：	成功则返回当前申请到的索引，否则返回-1
//////////////////////////////////////////////////////////////////////////

DWORD  AllocApiFromList(lpModInfo lpCurModNode)
{
	DWORD			dwApiIndex;
	DWORD			dwApiNum;
	lpApiInfo		pTemp;

	//如果没有申请Apilist，则进行申请，并且设置好索引和列表长度
	if (lpCurModNode->lpApiList == NULL)
	{
		if (lpCurModNode->dwApiListLen % LIST_API_INC)
		{
			dwApiNum = (lpCurModNode->dwApiListLen / LIST_API_INC + 1)*LIST_API_INC;
		}
		else
		{//加上增量，防止溢出等不可知内存异常情况
			dwApiNum = lpCurModNode->dwApiListLen + LIST_API_INC;
		}

		//注意，一定要申请到可执行的属性，不然detour后程序直接报异常
		lpCurModNode->lpApiList = (lpApiInfo)VirtualAlloc(NULL, sizeof(ApiInfo) * dwApiNum, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		
		if (lpCurModNode->lpApiList == NULL) return -1;

		ZeroMemory(lpCurModNode->lpApiList, sizeof(ApiInfo)*dwApiNum);

		lpCurModNode->dwApiListLen = dwApiNum;

		lpCurModNode->dwPrivateApiListIndex = 0;

	}//if



	pTemp		= lpCurModNode->lpApiList;
	dwApiIndex	= lpCurModNode->dwPrivateApiListIndex;

	pTemp[dwApiIndex].dwModIndex = lpCurModNode->dwModIndex;
	lpCurModNode->dwPrivateApiListIndex++;

	return dwApiIndex;
}


//////////////////////////////////////////////////////////////////////////
//	初始化ShellCode，填写shellCode的Opcode
//	参数：	
//	lpShellCode lpShell - 指向shellcode结构的指针
//////////////////////////////////////////////////////////////////////////

VOID	InitApiShellStruct(lpShellCode lpShell)
{
	lpShell->byPushadOpc	= 0x60;
	lpShell->byPushEsp		= 0x54;
	lpShell->byPushOpc1		= 0x68;
	lpShell->byPushOpc2		= 0x68;
	lpShell->byCallOpc		= 0xE8;
	lpShell->byJmpOpcApi	= 0xE9;
	lpShell->byPopadOpc		= 0x61;
	
}



//////////////////////////////////////////////////////////////////////////
//	卸载Detour的hook，还原原函数，使程序运行正常
//////////////////////////////////////////////////////////////////////////

BOOL UnHookAllApi()
{
	lpModInfo					lpCurModNode;
	lpApiInfo					lpApiList;
	HANDLE						hSnapShot;
	THREADENTRY32				stcThreadInfo;


	//1. 使用detour刷新线程
	DetourTransactionBegin();
	DetourSetIgnoreTooSmall(TRUE);

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

	if (hSnapShot != INVALID_HANDLE_VALUE)
	{
		if (Thread32First(hSnapShot, &stcThreadInfo))
		{
			DetourUpdateThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, stcThreadInfo.th32ThreadID));
			while (Thread32Next(hSnapShot, &stcThreadInfo))
			{
				DetourUpdateThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, stcThreadInfo.th32ThreadID));
			}
		}
	}


	//2. 遍历ModList
	for (DWORD dwModIndex = 0; dwModIndex < g_dwModListLen; dwModIndex ++ )
	{
		lpCurModNode	= &g_lpModList[dwModIndex];
		lpApiList		= lpCurModNode->lpApiList;
		OutputDebugString(lpCurModNode->szModName);
		if(lpCurModNode->lpApiList == NULL) continue;

		//2.1 遍历对应Mod的Apilist
		for (DWORD dwApiIndex = 0; dwApiIndex < lpCurModNode->dwApiListLen; dwApiIndex ++ )
		{

			if (lpApiList[dwApiIndex].bIsHooked)
			{
				DetourDetach((PVOID*)&lpApiList[dwApiIndex].dwApiRealAddr, lpApiList[dwApiIndex].lpShellBuf);
			}
		}
	}

	OutputDebugString(L"DetourDetach");

	if (DetourTransactionCommit() != NO_ERROR)
		return FALSE;
	

	return TRUE;

}


//////////////////////////////////////////////////////////////////////////
//	释放列表的空间
//	注：该操作必须在UnHookApi之后执行，否则会出现访问异常
//////////////////////////////////////////////////////////////////////////

BOOL FreeListMemory()
{
	lpModInfo	lpCurModNode;
	lpApiInfo	lpApiList;


	for (DWORD dwModIndex = 0; dwModIndex < g_dwModListLen; dwModIndex++)
	{
		lpCurModNode = &g_lpModList[dwModIndex];
		lpApiList = lpCurModNode->lpApiList;
		if (VirtualFree(lpApiList, 0, MEM_RELEASE) == 0) return FALSE;
	}
		
	if (VirtualFree(g_lpModList, 0, MEM_RELEASE) == 0)	return FALSE;

	return TRUE;

}

//////////////////////////////////////////////////////////////////////////
//	对指定模块进行Hook，包括对特殊API的过滤
//	参数：
//	DWORD			dwModIndex	 - 模块索引
//////////////////////////////////////////////////////////////////////////

VOID	HookModule(DWORD dwModIndex)
{
	//扫描内存中的模块
	//使用GetSystemInfo和VirtualQuery
	DWORD						dwPageAddr;



	MEMORY_BASIC_INFORMATION	stcMibOfApi;
	
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeader;
	PIMAGE_EXPORT_DIRECTORY		pExp;

	DWORD						dwWideCharSize;
	DWORD						dwCurModIndex;			//当前ModIndex
	DWORD						dwCurApiIndex;			//当前ApiIndex
	DWORD						dwCurModBaseAddr;		//当前模块的起始地址
	DWORD						dwCurModBaseEnd;		//当前模块的末地址
	PDWORD						dpExpAddrOfFunc;
	PDWORD						dpExpAddrOfName;
	PWORD						wpExpAddrOfNameOri;

	lpApiInfo					lpCurApiList;
	ShellCode					stcShellCode;

	HANDLE						hSnapShot;
	THREADENTRY32				stcThreadInfo;
	BOOL						bIgnoringHook;
	DWORD						dwNewAddr;
	DWORD						dwTrapAddr;



	//1.  Detour处理线程
	DetourTransactionBegin();
	DetourSetIgnoreTooSmall(TRUE);

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

	if (hSnapShot != INVALID_HANDLE_VALUE)
	{
		if (Thread32First(hSnapShot, &stcThreadInfo))
		{
			DetourUpdateThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, stcThreadInfo.th32ThreadID));
			while (Thread32Next(hSnapShot, &stcThreadInfo))
			{
				DetourUpdateThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, stcThreadInfo.th32ThreadID));
			}
		}
	}


	dwCurModIndex	= dwModIndex;
	dwPageAddr		= g_lpModList[dwCurModIndex].dwBaseAddr;
	//2.  对模块进行导出表的解析

	pDosHeader = (PIMAGE_DOS_HEADER)dwPageAddr;

	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + dwPageAddr);

	pExp = (PIMAGE_EXPORT_DIRECTORY)(dwPageAddr + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	dpExpAddrOfFunc = (PDWORD)(pExp->AddressOfFunctions + dwPageAddr);
	dpExpAddrOfName = (PDWORD)(pExp->AddressOfNames + dwPageAddr);
	wpExpAddrOfNameOri = (PWORD)(pExp->AddressOfNameOrdinals + dwPageAddr);
	g_lpModList[dwCurModIndex].dwApiListLen = pExp->NumberOfNames;

	// 当前模块的范围
	dwCurModBaseAddr	= dwPageAddr;
	dwCurModBaseEnd		= dwPageAddr + pNtHeader->OptionalHeader.SizeOfImage;


	//2.3 初始化Shellcode
	InitApiShellStruct(&stcShellCode);
	dwTrapAddr = (DWORD)GetProcAddress((HMODULE)dwSelfModBaseStart, "TrappedApiCall");


	for (DWORD i = 0; i < _countof(g_szFilteredDllList); i++)
	{
		if (_wcsnicmp(g_lpModList[dwCurModIndex].szModName,
			g_szFilteredDllList[i].szDllName,
			g_szFilteredDllList[i].dwCheckSize) == 0)
		{	
			return;
		}
	}


	//2.5 遍历模块的Api，添加API信息,只处理按字符串导出的Api
	for (DWORD dwIndex = 0; dwIndex < pExp->NumberOfNames; dwIndex++)
	{
		//预处理,默认Bu忽略Hook
		bIgnoringHook = FALSE;

		//地址是否在模块外，不知道有没有这种情况发生
		if ((dpExpAddrOfFunc[wpExpAddrOfNameOri[dwIndex]] + dwPageAddr) >= dwCurModBaseEnd ||
			(dpExpAddrOfFunc[wpExpAddrOfNameOri[dwIndex]] + dwPageAddr) <= dwCurModBaseAddr)
			continue;

		VirtualQuery((LPVOID)(dpExpAddrOfFunc[wpExpAddrOfNameOri[dwIndex]] + dwPageAddr),
			&stcMibOfApi,
			sizeof(MEMORY_BASIC_INFORMATION));

		//该Api是否可执行
		//	0xF0的意思，查看MSDN文档，只要是带有执行属性，都会在高4位设位
		//	只要让其属性&0xF0后只要为1，就可以说明该区域可以执行
		if (((stcMibOfApi.AllocationProtect & 0xF0) == 0) || stcMibOfApi.State != MEM_COMMIT)
			continue;


		//做完上述预处理后在申请节点
		dwCurApiIndex = AllocApiFromList(&g_lpModList[dwCurModIndex]);

		if (dwCurApiIndex == -1) continue;

		lpCurApiList = g_lpModList[dwCurModIndex].lpApiList;

		lpCurApiList[dwCurApiIndex].bIsHooked		= FALSE;			
		lpCurApiList[dwCurApiIndex].bIsFiltered		= FALSE;			//默认不过滤
		lpCurApiList[dwCurApiIndex].dwOridinal		= wpExpAddrOfNameOri[dwIndex];
		lpCurApiList[dwCurApiIndex].dwModIndex		= dwCurModIndex;
		lpCurApiList[dwCurApiIndex].dwApiIndex		= dwCurApiIndex;
		lpCurApiList[dwCurApiIndex].dwApiRealAddr	= dpExpAddrOfFunc[wpExpAddrOfNameOri[dwIndex]] + dwPageAddr;
		lpCurApiList[dwCurApiIndex].lpShellBuf		= NULL;

		dwWideCharSize = MultiByteToWideChar(CP_ACP, NULL, (CHAR*)(dwPageAddr + dpExpAddrOfName[dwIndex]), strlen((CHAR*)(dwPageAddr + dpExpAddrOfName[dwIndex])),
			NULL, NULL);

		MultiByteToWideChar(CP_ACP, NULL, (CHAR*)(dwPageAddr + dpExpAddrOfName[dwIndex]),
			strlen((CHAR*)(dwPageAddr + dpExpAddrOfName[dwIndex])),
			lpCurApiList[dwCurApiIndex].szApiName, dwWideCharSize);

		//2.6 发送Api相关信息(注：必须先发送在Hook，不然其Api真实地址会被Detour替换)
		SendApiInfo(&lpCurApiList[dwCurApiIndex]);

	
		//	特殊API过滤

		bIgnoringHook = FilterApi( g_lpModList[dwCurModIndex].szModName,
			lpCurApiList[dwCurApiIndex].szApiName);
		


		if (bIgnoringHook == FALSE)
		{

			OutputDebugString(L"Api:");
			OutputDebugString(lpCurApiList[dwCurApiIndex].szApiName);

			lpCurApiList[dwCurApiIndex].lpShellBuf = (lpShellCode)VirtualAlloc(NULL, sizeof(ShellCode),
				MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			stcShellCode.dwPushApiIndex = dwCurApiIndex;
			stcShellCode.dwPushModIndex = dwCurModIndex;


			stcShellCode.dwCallAddr = (DWORD)dwTrapAddr - ((DWORD)lpCurApiList[dwCurApiIndex].lpShellBuf + offsetof(ShellCode, dwCallAddr) + 4);
			stcShellCode.dwJmpApiAddr = lpCurApiList[dwCurApiIndex].dwApiRealAddr - ((DWORD)lpCurApiList[dwCurApiIndex].lpShellBuf + offsetof(ShellCode, dwJmpApiAddr) + 4);

			CopyMemory(lpCurApiList[dwCurApiIndex].lpShellBuf, &stcShellCode, sizeof(ShellCode));

			DetourAttachEx((PVOID*)&lpCurApiList[dwCurApiIndex].dwApiRealAddr,
				lpCurApiList[dwCurApiIndex].lpShellBuf,
				(PDETOUR_TRAMPOLINE*)&dwNewAddr, NULL, NULL);

			lpCurApiList[dwCurApiIndex].lpShellBuf->dwJmpApiAddr = dwNewAddr - ((DWORD)lpCurApiList[dwCurApiIndex].lpShellBuf + offsetof(ShellCode, dwJmpApiAddr) + 4);
			lpCurApiList[dwCurApiIndex].bIsHooked = TRUE;
		}
	}//for

	SendFinish(FINISH_APIMSG);	
	DetourTransactionCommit();
	g_lpModList[dwCurModIndex].bActive = TRUE;

}



//////////////////////////////////////////////////////////////////////////
//	对指定模块中的API进行UnHook
//	参数：	DWORD	dwModIndex	 - 模块索引
//	注意：对_ApiInfo中的IsHooked字段来判断
//////////////////////////////////////////////////////////////////////////
BOOL	UnHookModule(DWORD dwModIndex)
{
	lpModInfo					lpCurModNode;
	lpApiInfo					lpApiList;
	HANDLE						hSnapShot;
	THREADENTRY32				stcThreadInfo;


	//1. 使用detour刷新线程
	DetourTransactionBegin();
	DetourSetIgnoreTooSmall(TRUE);

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

	if (hSnapShot != INVALID_HANDLE_VALUE)
	{
		if (Thread32First(hSnapShot, &stcThreadInfo))
		{
			DetourUpdateThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, stcThreadInfo.th32ThreadID));
			while (Thread32Next(hSnapShot, &stcThreadInfo))
			{
				DetourUpdateThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, stcThreadInfo.th32ThreadID));
			}
		}
	}

		lpCurModNode	= &g_lpModList[dwModIndex];
		lpApiList		= lpCurModNode->lpApiList;

		//2.1 遍历对应Mod的Apilist
		for (DWORD dwApiIndex = 0; dwApiIndex < lpCurModNode->dwApiListLen; dwApiIndex++)
		{
			if (lpApiList[dwApiIndex].bIsHooked)
			{
				DetourDetach((PVOID*)&lpApiList[dwApiIndex].dwApiRealAddr, lpApiList[dwApiIndex].lpShellBuf);
				lpApiList[dwApiIndex].bIsHooked = FALSE;
			}
		}
	


	if (DetourTransactionCommit() != NO_ERROR)
		return FALSE;


	return TRUE;
}




//////////////////////////////////////////////////////////////////////////
//	发送模块信息到监控端，传入当前Mod节点的结构体，由该模块进行数据包封装
//	成PcketModInfo发送至另一端
//	参数：
//	lpModInfo lpCurModNode - 当前Mod节点的结构体
//////////////////////////////////////////////////////////////////////////


VOID SendModInfo(lpModInfo lpCurModNode)
{
	lpPacketModInfo lpCurModInfo;
	lpPacketInfo	lpCurPacket;
	DWORD			dwTotalLength;
	DWORD			dwBytesOfWritten;
	//先封装PacketModInfo
	lpCurModInfo = new PacketModInfo;
	lpCurModInfo->dwBaseAddr	= lpCurModNode->dwBaseAddr;
	lpCurModInfo->dwImageSize	= lpCurModNode->dwImageSize;
	lpCurModInfo->dwModIndex	= lpCurModNode->dwModIndex;
	
	//注意，要初始化dll字符串数组，不然会出现意想不到的问题
	ZeroMemory(lpCurModInfo->szModName, sizeof(WCHAR)*MAX_NAME_LEN);

	//注意：在所有过程中，都是默认以宽字符来进行传输,节省转换操作
	wcscpy_s(lpCurModInfo->szModName, lpCurModNode->szModName);

	//进一步封装PacketInfo，定义消息类型和数据长度
	dwTotalLength = sizeof(PacketModInfo) + sizeof(PacketInfo);
	lpCurPacket = (lpPacketInfo) new BYTE[dwTotalLength];
	lpCurPacket->dwType = MOD_MSG;
	lpCurPacket->dwLegth = sizeof(PacketModInfo);

	CopyMemory(lpCurPacket->Data, lpCurModInfo, lpCurPacket->dwLegth);

	WriteFile(g_hPipe2, lpCurPacket, dwTotalLength, &dwBytesOfWritten, NULL);

	
}


//////////////////////////////////////////////////////////////////////////
//	发送Api信息至监控端，传入当前Api节点信息，该模块进行封包处理
//	参数：
//	lpApiInfo lpCurApiNode - Api节点的结构体
//////////////////////////////////////////////////////////////////////////

VOID SendApiInfo(lpApiInfo lpCurApiNode)
{
	lpPacketApiInfo lpCurApiInfo;
	lpPacketInfo	lpCurPacket;
	DWORD			dwTotalLength;
	DWORD			dwBytesOfWritten;

	//先封装PacketApiInfo，包含了Api的关键信息
	lpCurApiInfo = new PacketApiInfo;
	lpCurApiInfo->dwApiIndex	= lpCurApiNode->dwApiIndex;
	lpCurApiInfo->dwApiRealAddr = lpCurApiNode->dwApiRealAddr;
	lpCurApiInfo->dwModIndex	= lpCurApiNode->dwModIndex;
	lpCurApiInfo->dwOridinal	= lpCurApiNode->dwOridinal;
	
	wcscpy_s(lpCurApiInfo->szApiName, lpCurApiNode->szApiName);

	//进一步封装PacketInfo
	dwTotalLength = sizeof(PacketApiInfo) + sizeof(PacketInfo);
	lpCurPacket = (lpPacketInfo)new BYTE[dwTotalLength];

	lpCurPacket->dwType = API_MSG;
	lpCurPacket->dwLegth = sizeof(PacketApiInfo);

	CopyMemory(lpCurPacket->Data, lpCurApiInfo, lpCurPacket->dwLegth);

	WriteFile(g_hPipe2, lpCurPacket, dwTotalLength, &dwBytesOfWritten, NULL);
}



//////////////////////////////////////////////////////////////////////////
//	判断该Api是否是过滤的，先进行模块过滤检测，然后接着检测Api过滤
//	参数：
//	DWORD dwModIndex - 该Api对应的Mod索引
//	DWORD dwApiIndex - 该Api的Apilist中的索引
//	返回值：	若是过滤Api，则返回TRUE，否则FALSE
//////////////////////////////////////////////////////////////////////////

BOOL IsFilteredApi(DWORD dwModIndex, DWORD dwApiIndex)
{
	lpApiInfo	lpCurApiNode;

	////该Api对应的模块是否被过滤？
	//if (g_lpModList[dwModIndex].bIsFiltered == TRUE)	return TRUE;

	lpCurApiNode = &g_lpModList[dwModIndex].lpApiList[dwApiIndex];

	if (lpCurApiNode->bIsFiltered == TRUE)	return TRUE;

	return FALSE;
}


//////////////////////////////////////////////////////////////////////////
//	封装Api调用触发信息，信息包含返回地址，模块索引，Api索引(调用参数)
//	参数：
//	VOID* pStack		- 该Api的堆栈指针
//	DWORD dwModIndex	- 该Api对应的Mod索引
//	DWORD dwApiIndex	- 该Api自身的索引
//////////////////////////////////////////////////////////////////////////

VOID SendTrapInfo(VOID* pStack, DWORD dwModIndex, DWORD dwApiIndex, WCHAR* szParam)
{
	lpPacketTrapInfo	lpCurTrap;
	lpPacketInfo		lpCurPacket;
	DWORD				dwTotalLength;
	DWORD				dwBytesOfWritten;
	DWORD				dwParamLen;


	if (szParam != NULL)
		dwParamLen = (wcslen(szParam) + 1)*sizeof(WCHAR);
	else
		dwParamLen = 0;

	lpCurTrap = (lpPacketTrapInfo)new BYTE [sizeof(PacketTrapInfo) + dwParamLen];
	lpCurTrap->dwModIndex	= dwModIndex;
	lpCurTrap->dwApiIndex	= dwApiIndex;
	lpCurTrap->dwRetAddr	= *(PDWORD)pStack;
	lpCurTrap->dwLength		= dwParamLen;

	if (szParam != NULL)
		lstrcpyn((WCHAR*)lpCurTrap->byPara, szParam, wcslen(szParam) + 1);
	else
		lpCurTrap->byPara[0] = 0x0;
	

	dwTotalLength = sizeof(PacketTrapInfo) + sizeof(PacketInfo) + dwParamLen;
	lpCurPacket = (lpPacketInfo)new BYTE[dwTotalLength];

	lpCurPacket->dwType = TRAP_MSG;
	lpCurPacket->dwLegth = sizeof(PacketTrapInfo) + dwParamLen;
	
	CopyMemory(lpCurPacket->Data, lpCurTrap, lpCurPacket->dwLegth);

	WriteFile(g_hPipe2, lpCurPacket, dwTotalLength, &dwBytesOfWritten, NULL);
	delete lpCurPacket;
	delete lpCurTrap;
}


//////////////////////////////////////////////////////////////////////////
//	发出该消息表明MOD数据和API数据已经传送完毕，可以让监控端的UI进行生成
//	设计原因：如果让监控端每次在接收到数据后都直接生成，会导致卡顿和只能显示
//	部分信息，不如让其直接接收完全部在进行UI生成，效率相对较高
//////////////////////////////////////////////////////////////////////////

VOID SendFinish(DWORD	dwType)
{
	lpPacketInfo		lpCurPacket;
	DWORD				dwTotalLength;
	DWORD				dwBytesOfWritten;

	dwTotalLength = sizeof(PacketInfo);
	lpCurPacket = (lpPacketInfo)new BYTE[dwTotalLength];
	lpCurPacket->dwType = dwType;
	lpCurPacket->dwLegth = 0;

	WriteFile(g_hPipe2, lpCurPacket, dwTotalLength, &dwBytesOfWritten, NULL);
}





//////////////////////////////////////////////////////////////////////////
//	触发函数，提取Api的调用参数，返回地址
//	参数：
//	DWORD dwModIndex - 模块索引，用于g_lpModList
//	DWORD dwApiIndex - Api索引，用于对应Mod中的Apilist
//	VOID* pStack - Api堆栈的指针
//////////////////////////////////////////////////////////////////////////

extern "C"  VOID  __stdcall TrappedApiCall(DWORD dwModIndex, DWORD dwApiIndex, VOID* pStack)
{
	WCHAR*	szParam;
	if (IsHookCallAgain)				//检测是否由于TrappedApiCall()内有调用函数被Hook而引起的循环调用
	{
		return	;						//如果检测到循环调用，则函数直接返回
	}
	else
	{
		IsHookCallAgain = TRUE;
	}

	pStack = (VOID*)((DWORD)pStack + 0x20);

	//过滤检测
	if (IsFilteredApi(dwModIndex, dwApiIndex) == TRUE)
	{

		IsHookCallAgain = FALSE;
		return;
	}


	szParam = GetApiParam(g_lpModList[dwModIndex].szModName, g_lpModList[dwModIndex].lpApiList[dwApiIndex].szApiName,
		pStack);
	
	
	//发送触发信息至监控端
	SendTrapInfo(pStack, dwModIndex, dwApiIndex, szParam);

	if (szParam != NULL)
	{
		//OutputDebugString(szParam);
		VirtualFree(szParam, 0, MEM_RELEASE);
	}


	IsHookCallAgain = FALSE;
}




//////////////////////////////////////////////////////////////////////////
//	重新对指定模块进行Hook，目的是避免重新为该模块申请和发送API消息，只
//	处理DetourAttach
//	参数：
//	DWORD		dwModIndex		 - 指定模块的索引
//////////////////////////////////////////////////////////////////////////


VOID	ReHookModule(DWORD dwModIndex)
{
	DWORD						dwCurModIndex;			//当前ModIndex
	DWORD						dwCurApiIndex;			//当前ApiIndex
	lpApiInfo					lpCurApiList;
	HANDLE						hSnapShot;
	THREADENTRY32				stcThreadInfo;
	BOOL						bIgnoringHook;
	DWORD						dwNewAddr;


	//1.  Detour处理线程
	DetourTransactionBegin();
	DetourSetIgnoreTooSmall(TRUE);

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

	if (hSnapShot != INVALID_HANDLE_VALUE)
	{
		if (Thread32First(hSnapShot, &stcThreadInfo))
		{
			DetourUpdateThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, stcThreadInfo.th32ThreadID));
			while (Thread32Next(hSnapShot, &stcThreadInfo))
			{
				DetourUpdateThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, stcThreadInfo.th32ThreadID));
			}
		}
	}


	//2. 处理关键变量
	dwCurModIndex	= dwModIndex;
	lpCurApiList	= g_lpModList[dwCurModIndex].lpApiList;


	for (DWORD i = 0; i < _countof(g_szFilteredDllList); i++)
	{
		if (_wcsnicmp(g_lpModList[dwCurModIndex].szModName,
			g_szFilteredDllList[i].szDllName,
			g_szFilteredDllList[i].dwCheckSize) == 0)
		{
			return;
		}
	}



	for (DWORD dwIndex = 0; dwIndex < g_lpModList[dwCurModIndex].dwPrivateApiListIndex; dwIndex++)
	{
		if( wcslen(lpCurApiList[dwIndex].szApiName) == 0)	break;

		bIgnoringHook = FALSE;

		dwCurApiIndex = dwIndex;
		//////////////////////////////////////////////////////////////////////////
		//	过滤特殊api
		//////////////////////////////////////////////////////////////////////////

		bIgnoringHook = FilterApi(g_lpModList[dwCurModIndex].szModName , 
			lpCurApiList[dwCurApiIndex].szApiName);


		if (bIgnoringHook == FALSE)
		{
			DetourAttachEx((PVOID*)&lpCurApiList[dwCurApiIndex].dwApiRealAddr,
				lpCurApiList[dwCurApiIndex].lpShellBuf,
				(PDETOUR_TRAMPOLINE*)&dwNewAddr, NULL, NULL);
			lpCurApiList[dwCurApiIndex].lpShellBuf->dwJmpApiAddr = dwNewAddr - ((DWORD)lpCurApiList[dwCurApiIndex].lpShellBuf + offsetof(ShellCode, dwJmpApiAddr) + 4);
			lpCurApiList[dwCurApiIndex].bIsHooked = TRUE;
		}


	}

	DetourTransactionCommit();
}



//////////////////////////////////////////////////////////////////////////
//	判断指定的API是否需要过滤
//	参数：
//	WCHAR* szModName - API所属模块名
//	WCHAR* szApiName - api名
//	返回值：过滤则返回TRUE，否则FLASE
//////////////////////////////////////////////////////////////////////////

BOOL	FilterApi(WCHAR* szModName, WCHAR* szApiName)
{
	BOOL	bIgnoringHook = FALSE;
	BOOL	bExistInSS;
	WCHAR*	pOffset;
	WCHAR	szTest[MAX_PATH] = { 0 };

	bExistInSS = FALSE;

	//检测ss文件中是否存在该模块的配置信息，若没有，直接视为全部的API都不可HOOK
	for (DWORD dwModIndex = 0; dwModIndex < g_dwDefNUm; dwModIndex++)
	{
		if (_wcsnicmp(g_stcDef[dwModIndex].szDefFileObject, szModName, wcslen(g_stcDef[dwModIndex].szDefFileObject)) == 0)
		{//找到模块
			bExistInSS = TRUE;
			break;
		}
	}


	if (bExistInSS == FALSE)
	{//不存在，返回可HOOK
		return TRUE;
	}

	//存在该模块的配置文件，过滤不需要分析的API
	for (DWORD dwModIndex = 0; dwModIndex < g_dwDefNUm ; dwModIndex++)
	{
		if (_wcsnicmp(g_stcDef[dwModIndex].szDefFileObject, szModName, wcslen(g_stcDef[dwModIndex].szDefFileObject)) == 0)
		{//找到模块
			if ((pOffset = wcsstr((WCHAR*)g_stcDef[dwModIndex].lpMapAddress, szApiName)) == NULL)
			{//没找到API
				bIgnoringHook = TRUE;
				return bIgnoringHook;
			}
			else
			{
				//找到前缀，进一步检查API名是否完全匹配
				if (_wcsnicmp(pOffset, szApiName, (DWORD)(wcsstr(pOffset, L"\r") - pOffset)) != 0)
				{
					bIgnoringHook = TRUE;
					return bIgnoringHook;
				}//if
			}//if
		}//if
		
	}//while

	return bIgnoringHook;

}


//BOOL	FilterApi(WCHAR* szModName, WCHAR* szApiName)
//{
//	BOOL	bIgnoringHook = FALSE;
//
//	//user32
//	if (wcscmp(L"gapfnScSendMessage", szApiName) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"OffsetRect", szApiName, wcslen(L"OffsetRect")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"IsRectEmpty", szApiName, wcslen(L"IsRectEmpty")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"GetWindowLong", szApiName, wcslen(L"GetWindowLong")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"GetParent", szApiName, wcslen(L"GetParent")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"IsWindow", szApiName, wcslen(L"IsWindow")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"SetWindowLong", szApiName, wcslen(L"SetWindowLong")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"GetKeyboardLayout", szApiName, wcslen(L"GetKeyboardLayout")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"SendMessage", szApiName, wcslen(L"SendMessage")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"GetClientRect", szApiName, wcslen(L"GetClientRect")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"GetWindow", szApiName, wcslen(L"GetWindow")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"PeekMessage", szApiName, wcslen(L"PeekMessage")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"IsDialogMessage", szApiName, wcslen(L"IsDialogMessage")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"GetSystemMetrics", szApiName, wcslen(L"IsDialogMessage")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"UnregisterClass", szApiName, wcslen(L"UnregisterClass")) == 0)
//		bIgnoringHook = TRUE;
//	
//	if (_wcsnicmp(L"CallWindowProc", szApiName, wcslen(L"CallWindowProc")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"GetProp", szApiName, wcslen(L"GetProp")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"SystemParametersInfo", szApiName, wcslen(L"SystemParametersInfo")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"GetDpiForSystem", szApiName, wcslen(L"GetDpiForSystem")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"GetSysColor", szApiName, wcslen(L"GetSysColor")) == 0)
//		bIgnoringHook = TRUE;
//	
//	if (_wcsnicmp(L"IsProcessDPIAware", szApiName, wcslen(L"IsProcessDPIAware")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"TranslateMessage", szApiName, wcslen(L"TranslateMessage")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"DispatchMessage", szApiName, wcslen(L"DispatchMessage")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"GetDlgCtrlID", szApiName, wcslen(L"GetDlgCtrlID")) == 0)
//		bIgnoringHook = TRUE;
//	
//	if (_wcsnicmp(L"GetMessage", szApiName, wcslen(L"GetMessage")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"IsThreadDesktopComposited", szApiName, wcslen(L"IsThreadDesktopComposited")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"SetProp", szApiName, wcslen(L"SetProp")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"PtInRect", szApiName, wcslen(L"PtInRect")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"ClientToScreen", szApiName, wcslen(L"ClientToScreen")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"CallMsgFilter", szApiName, wcslen(L"CallMsgFilter")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"IsTopLevelWindow", szApiName, wcslen(L"IsTopLevelWindow")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"WaitMessage", szApiName, wcslen(L"WaitMessage")) == 0)
//		bIgnoringHook = TRUE;
//
//
//	//msvcrt
//
//	if (_wcsnicmp(L"_osver", szApiName, wcslen(L"_osver")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"_environ", szApiName, wcslen(L"_environ")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"_iob", szApiName, wcslen(L"_iob")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"__threadid", szApiName, wcslen(L"__threadid")) == 0)
//		bIgnoringHook = TRUE;
//
//	//	__pioinfo
//	if (_wcsnicmp(L"__pioinfo", szApiName, wcslen(L"__pioinfo")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"_acmdln", szApiName, wcslen(L"_acmdln")) == 0)
//		bIgnoringHook = TRUE;
//
//
//
//
//	//kernel32
//
//	if (wcscmp(L"BaseFormatObjectAttributes", szApiName) == 0)
//		bIgnoringHook = TRUE;
//
//	if (wcscmp(L"DuplicateHandle", szApiName) == 0)
//		bIgnoringHook = TRUE;
//
//	if (wcscmp(L"HeapFree", szApiName) == 0)
//		bIgnoringHook = TRUE;
//
//	if (wcscmp(L"ReleaseMutex", szApiName) == 0)
//		bIgnoringHook = TRUE;
//
//	if (wcscmp(L"Sleep", szApiName) == 0)
//		bIgnoringHook = TRUE;
//	//kernel32
//	if (_wcsnicmp(L"OutputDebugString", szApiName, 17) == 0)
//		bIgnoringHook = TRUE;
//	//kernel32
//	if (_wcsnicmp(L"GetLastError", szApiName, 12) == 0)
//		bIgnoringHook = TRUE;
//	//kernel32
//	if (_wcsnicmp(L"wow64", szApiName, 5) == 0)
//		bIgnoringHook = TRUE;
//	//kernel32
//
//
//	if (_wcsnicmp(L"CreateEvent ", szApiName, wcslen(L"CreateEvent")) == 0)
//		bIgnoringHook = TRUE;
//
//
//
//	if (_wcsnicmp(L"GlobalFindAtom ", szApiName, wcslen(L"GlobalFindAtom")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"FlushInstructionCache ", szApiName, wcslen(L"FlushInstructionCache")) == 0)
//		bIgnoringHook = TRUE;
//	//kernel32
//	if (_wcsnicmp(L"AddRefActCtxWorker ", szApiName, wcslen(L"AddRefActCtxWorker")) == 0)
//		bIgnoringHook = TRUE;
//	//kernel32
//	if (_wcsnicmp(L"SetLastError", szApiName, wcslen(L"SetLastError")) == 0)
//		bIgnoringHook = TRUE;
//	//kernel32
//	if (_wcsnicmp(L"tls", szApiName, wcslen(L"tls")) == 0)
//		bIgnoringHook = TRUE;
//	//kernel32
//	if (_wcsnicmp(L"Rtl", szApiName, wcslen(L"Rtl")) == 0)
//		bIgnoringHook = TRUE;
//	//kernel32
//	if (_wcsnicmp(L"RaiseException", szApiName, wcslen(L"RaiseException")) == 0)
//		bIgnoringHook = TRUE;
//	//kernel32
//	if (_wcsnicmp(L"WaitFor", szApiName, wcslen(L"WaitFor")) == 0)
//		bIgnoringHook = TRUE;
//	//kernel32
//	if (_wcsnicmp(L"VirtualProtect", szApiName, wcslen(L"VirtualProtect")) == 0)
//		bIgnoringHook = TRUE;
//	//kernelbase
//	if (_wcsnicmp(L"HeapValidate", szApiName, wcslen(L"HeapValidate")) == 0)
//		bIgnoringHook = TRUE;
//	//ws2_32.dll
//	if (_wcsnicmp(L"WSASetLastError", szApiName, wcslen(L"WSASetLastError")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"WSAGetLastError ", szApiName, wcslen(L"WSASetLastError")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"_toupper", szApiName, wcslen(L"_toupper")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"_tolower", szApiName, wcslen(L"_tolower")) == 0)
//		bIgnoringHook = TRUE;
//
//	if (_wcsnicmp(L"_CrtIsValidHeapPointer", szApiName, wcslen(L"_CrtIsValidHeapPointer")) == 0)
//		bIgnoringHook = TRUE;
//
//
//	return bIgnoringHook;
//
//
//}
// SaerPackBase.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "SaerPackBase.h"
#include "resource.h"


SAERPACKBASE_API BOOL PackBase(LPWSTR strPath, PSelectionInfo pSelect)
{
	COperationPE	stcObjectPE; //宿主程序的 PE处理对象
	PEInfo			stcPeInfo = { 0 }; // PE信息
	HANDLE  hFile_In;
	HANDLE  hFile_Out;
	DWORD   dwFileSize;
	LPBYTE  pFileImage;
	WCHAR   szOutPath[MAX_PATH] = { 0 };
	// 1. 生成输出文件路径

	LPWSTR strSuffix = PathFindExtension(strPath);				// 获取文件的后缀名
	wcsncpy_s(szOutPath, MAX_PATH, strPath, wcslen(strPath));	// 备份目标文件路径到szOutPath
	PathRemoveExtension(szOutPath);								// 将szOutPath中保存路径的后缀名去掉
	wcscat_s(szOutPath, MAX_PATH, L"_Pack");					// 在路径最后附加“_Pack”
	wcscat_s(szOutPath, MAX_PATH, strSuffix);					// 在路径最后附加刚刚保存的后缀名
	LPWSTR strFileName = PathFindFileName(szOutPath);			// 获取修改后的文件名
	OutputDebugString(L"生成输出文件路径");

	//1.2 获取资源形式的DLL的大小
	// 1. 在资源中读取文件内容
	HRSRC   hREC = NULL; // 资源对象
	HGLOBAL hREC_Handle = NULL; // 资源句柄
	DWORD   dwShellFileSize = NULL; // 文件大小
	LPVOID  pResData = NULL; // 资源数据指针
	HMODULE hModule = GetModuleHandle(L"SaerPackBase.dll");



	if (!(hREC = FindResource(hModule, MAKEINTRESOURCE(IDR_SHELL1), L"SHELL")))  return FALSE;
	if (!(hREC_Handle = LoadResource(hModule, hREC)))							 return FALSE;
	if (!(pResData = LockResource(hREC_Handle)))								 return FALSE;
	if (!(dwShellFileSize = SizeofResource(hModule, hREC)))							 return FALSE;



	// 2. 获取文件信息，并映射进内存中
	if (INVALID_HANDLE_VALUE == (hFile_In = CreateFile(strPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)))
	{
		return false;
	}

	if (INVALID_FILE_SIZE == (dwFileSize = GetFileSize(hFile_In, NULL)))
	{
		CloseHandle(hFile_In);
		return false;
	}

	//15000的空间使为代码乱序准备的
	if (!(pFileImage = (LPBYTE)VirtualAlloc(NULL, dwFileSize * 5 + dwShellFileSize + 15000, MEM_COMMIT, PAGE_READWRITE)))
	{
		CloseHandle(hFile_In);
		return false;
	}

	DWORD dwRet;


	if (!ReadFile(hFile_In, pFileImage, dwFileSize, &dwRet, NULL))
	{
		CloseHandle(hFile_In);
		VirtualFree(pFileImage, 0, MEM_RELEASE);
		return false;
	}

	OutputDebugString(L"获取文件信息，并映射进内存中");


	// 3. 获取PE文件信息

	ZeroMemory(&stcPeInfo, sizeof(PEInfo));

	if (stcObjectPE.GetPEInfo(pFileImage, dwFileSize, &stcPeInfo) == FALSE)
		return FALSE;
	
	OutputDebugString(L"获取PE文件信息");


	// 4. 获取目标文件代码段的起始结束信息
	//    读取第一个区段的相关信息，并将其加密（默认第一个区段为代码段）
	DWORD	dwVirtualSize;
	if (!strncmp((CHAR*)stcPeInfo.pSectionHeader->Name, ".textbss", strlen(".textbss")))
	{//若第一个区段不是textbss，则下移一个区段
		stcPeInfo.pSectionHeader = stcPeInfo.pSectionHeader + 1;
	}
	

	if (stcPeInfo.pSectionHeader->Misc.VirtualSize % stcPeInfo.dwSectionAlign)
	{
		dwVirtualSize = (stcPeInfo.pSectionHeader->Misc.VirtualSize / stcPeInfo.dwSectionAlign + 1) * stcPeInfo.dwSectionAlign;
	}
	else
	{
		dwVirtualSize = (stcPeInfo.pSectionHeader->Misc.VirtualSize / stcPeInfo.dwSectionAlign) * stcPeInfo.dwSectionAlign;
	}

	LPBYTE pRawStart		= (LPBYTE)(stcPeInfo.pSectionHeader->PointerToRawData + (DWORD)pFileImage);
	LPBYTE pRawEnd			= (LPBYTE)((DWORD)pRawStart + stcPeInfo.pSectionHeader->SizeOfRawData);
	LPBYTE pVirtualStart	= (LPBYTE)(stcPeInfo.pSectionHeader->VirtualAddress);
	LPBYTE pVirtualEnd		= (LPBYTE)((DWORD)pVirtualStart + dwVirtualSize);

	stcPeInfo.dwCodeSize	= (DWORD)pVirtualEnd - (DWORD)pVirtualStart;	//以内存粒度对齐后的大小
	stcPeInfo.dwCodeBase	= (DWORD)pVirtualStart;

	OutputDebugString(L"代码段操作");


	// 5. 对文件进行预处理
	//压缩区段，修改区段表,代码乱序
	Pretreatment(pRawStart, pRawEnd, &stcObjectPE ,&stcPeInfo,  pSelect);

	//5.1 更新下文件大小，因为代码乱序会增加区段，使得原文件体积产生变化
	dwFileSize = stcObjectPE.GetFileRawSize();

	OutputDebugString(L"文件进行预处理");

	// 6. 植入Shell
	DWORD        dwShellSize = 0;
	SHELL_DATA	 stcParam = { 0 };
	stcParam.dwImageBase		= stcPeInfo.dwImageBase;
	stcParam.dwOldOEP			= stcPeInfo.dwOEP;			//原程序OEP
	stcParam.dwCodeBase			= stcPeInfo.dwCodeBase;
	stcParam.dwCodeSize			= stcPeInfo.dwCodeSize;
	stcParam.dwCodeRawSize		= stcPeInfo.dwCodeRawSize;
	stcParam.stcPEImportDir		= stcPeInfo.stcPEImportDir;
	stcParam.stcPERelocDir		= stcPeInfo.stcPERelocDir;
	stcParam.stcPEResDir		= stcPeInfo.stcPEResDir;
	stcParam.stcPETlsDir		= stcPeInfo.stcPETlsDir;
	stcParam.stcIATDir			= stcPeInfo.stcIATDir;
	stcParam.dwNumOfSections	= stcPeInfo.dwNumOfSections;
	//保存用户配置参数
	CopyMemory(&stcParam.stcConfig, pSelect, sizeof(SelectionInfo));
	
	dwShellSize = Implantation(strFileName, dwFileSize, &stcObjectPE, stcPeInfo, &stcParam, pSelect);
	
	OutputDebugString(L"植入Shell");

	// 7.清除不需要的表
	stcObjectPE.CleanDir();


	// 8. 计算CRC32校验码
	stcObjectPE.CalAndSaveCRC(dwShellSize + dwFileSize);
	

	OutputDebugString(L"清除不需要的表");

	// 9. 将处理完成后的结果写入到新文件中
	DWORD dwError;
	if (INVALID_HANDLE_VALUE != (hFile_Out = CreateFile(szOutPath, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL)))
	{
		DWORD dwRet = 0;
	
		WriteFile(hFile_Out, pFileImage, dwShellSize + dwFileSize, &dwRet, NULL);
		dwError = GetLastError();
	}




	
	OutputDebugString(L"将处理完成后的结果写入到新文件中");

	// 9. 释放相关资源并返回
	CloseHandle(hFile_In);
	CloseHandle(hFile_Out);
	VirtualFree(pFileImage, 0, MEM_RELEASE);

	OutputDebugString(L"释放相关资源并返回");

	return TRUE;
}


//////////////////////////////////////////////////////////////////////////
//	预处理，修改代码段属性为可读可写可执行
//	对代码段进行简单的抑或加密,并且压缩区段
//	参数：
//	LPBYTE				pCodeStart		代码段的起始地址
//	LPBYTE				pCodeEnd		代码段的末地址
//	COperationPE*		pObejctPE		宿主程序的PE操作类
//	pPEInfo				pPeInfo			[out]关键信息结构
//	PSelectionInfo		pSelect			配置信息
//////////////////////////////////////////////////////////////////////////


VOID	Pretreatment(LPBYTE pCodeStart, LPBYTE pCodeEnd, COperationPE* pObjectPE, pPEInfo pPeInfo, PSelectionInfo pSelect)
{
	// 1.1备份导出表数据
	
	if (pPeInfo->bIsDll)
	{
		pObjectPE->GetExportBuf(pPeInfo);
	}

	// 1.2 更新下私有变量中的PeInfo结构体
	pObjectPE->GetPEInfo(NULL, NULL, pPeInfo);

	// 1.3 保存宿主程序的tls数据
	pObjectPE->ReturnTlsModuleAddress(&pPeInfo->dwTlsModStart, &pPeInfo->dwTlsModEnd, &pPeInfo->dwTlsIndexValue); 

	// 1.4 转储导入表

		DWORD	dwIATBase;
		DWORD	dwIATSize;
		LPBYTE	pNewAddr;
		DWORD	dwNewIATSize = 0;

		//注意，在此处获得的IAT所在段才是正确的
		pObjectPE->FindSectionOfIAT(&dwIATBase, &dwIATSize);

		
		pPeInfo->dwOrigIATBase = dwIATBase;
		pPeInfo->dwOrigIATSize = dwIATSize;

		if (pSelect->bIsTransferIAT)
		{
			dwIATSize = pObjectPE->AlignSize(dwIATSize, pPeInfo->dwSectionAlign);
			pNewAddr = new BYTE[dwIATSize];
			ZeroMemory(pNewAddr, dwIATSize);
			dwNewIATSize = pObjectPE->MoveImportTable((DWORD)pNewAddr);
			pObjectPE->CleanImportTable();
			pPeInfo->pNewIATAddr = pNewAddr;
			pPeInfo->dwNewIATSize = dwNewIATSize;
		}


	// 1.5 转储重定位表
	if (pPeInfo->stcPERelocDir.VirtualAddress)
		if(pSelect->bIsTransferReloc)
	{//如果存在重定位表的话
		LPBYTE	pNewRelocAddr = new BYTE[pPeInfo->stcPERelocDir.Size];
		DWORD	dwNewRelocSize;

		ZeroMemory(pNewRelocAddr, pPeInfo->stcPERelocDir.Size);
		dwNewRelocSize = pObjectPE->MoveRelocTable((DWORD)pNewRelocAddr);
		pPeInfo->pNewRelocAddr	= pNewRelocAddr;
		pPeInfo->dwNewRelocSize = dwNewRelocSize;
		pObjectPE->CleanRelocTable();
	}


	//2. 代码乱序引擎
	pCode_Flow_Node			pCodeFlowHeader = NULL;
	WCHAR					szModPrefix[MAX_PATH];
	WCHAR					szConfig[MAX_PATH];
	DWORD					dwAvg;
	DWORD					dwNumOfNode;
	DWORD					dwNumOfMod;
	DWORD					dwRawSize;
	PDWORD					pdArrayMod;
	IMAGE_SECTION_HEADER	stcNewSectionOfJunkCode;
	LPBYTE					pNewSection = NULL;

	pSample_Array			pSampleArray = NULL;
	DWORD					dwTotalCtr;


	if (pSelect->bIsVirtualizeCode)
	{
		//2.1 反汇编处理
		pCodeFlowHeader = DrawCodeFlow(pObjectPE, pPeInfo, pCodeStart, pCodeEnd - pCodeStart);

		//2.2 计算出花指令模板平均长度

		ZeroMemory(szModPrefix, sizeof(WCHAR)*MAX_PATH);

		if (GetConfigPath(szConfig, MAX_PATH) == FALSE)
		{
			MessageBox(NULL, L"GetConfigPath Error", L"Error", NULL);
			exit(0);
		}

		dwAvg = CalcAverageVal(szConfig, szModPrefix, &dwNumOfMod, &pdArrayMod);

		if (dwAvg == -1)
		{
			MessageBox(NULL, L"CalcAverageVal Error", L"Error", NULL);
			exit(0);
		}

		//2.3 估算花指令区段长度，并添加至目标程序

		dwNumOfNode = GetNumOfNode(pCodeFlowHeader);

		if (dwNumOfNode != 0)
		{

			if (dwNumOfNode >= 100)
			{//限制区段大小,有些程序的节点会达到几万个，
				dwNumOfNode = 100;
			}

			pNewSection = pObjectPE->AddSection(L".pack4", dwNumOfNode * dwAvg,
				IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
				&stcNewSectionOfJunkCode,
				&dwRawSize);

			pObjectPE->GetPEInfo(NULL, NULL, pPeInfo);

			//2.4 乱序处理

			//读取样本数据
			pSampleArray = AnalyseSample(pSelect->szSample, &dwTotalCtr);


			if (ConfuseCode(pCodeFlowHeader, pObjectPE, pPeInfo, pNewSection, &stcNewSectionOfJunkCode,
				dwNumOfMod, szModPrefix, pdArrayMod, pSampleArray, dwTotalCtr) == FALSE)
			{
				MessageBox(NULL, L"ConfuseCode Error", L"Error", NULL);
				exit(0);
			}
		}//if

		ReleaseCodeFlow(pCodeFlowHeader);
		ReleaseSampleArray(pSampleArray, dwTotalCtr);
	}

	// 3. 加密指定区域
	//	3.1 计算内存中代码段的校验值 - CRC32
	LPBYTE	pCode = NULL;



	pCode = (LPBYTE)VirtualAlloc(NULL, pPeInfo->dwCodeSize, MEM_COMMIT, PAGE_READWRITE);
	if (pCode != NULL)
	{

		ZeroMemory(pCode, pPeInfo->dwCodeSize);

		CopyMemory(pCode, pCodeStart, pCodeEnd - pCodeStart);
			
		pObjectPE->CalMemCRC(pCode, pPeInfo->dwCodeSize, pPeInfo);

		VirtualFree(pCode, 0, MEM_RELEASE);
	}

	//	考虑以后给转储的IAT加密
	pPeInfo->dwCodeRawSize = pCodeEnd - pCodeStart;

	
	for (DWORD i=0; pCodeStart + i < pCodeEnd; i++)
	{
		pCodeStart[i] ^= i ;
	}

	

	// 4. 给代码段附加上可写属性
	PDWORD pChara = &(pPeInfo->pSectionHeader->Characteristics);
	*pChara = *pChara | IMAGE_SCN_MEM_WRITE;

	// 5. 重建资源表
	if(pPeInfo->stcPEResDir.Size != 0)
	pObjectPE->ReBuildRes(pPeInfo);

	// 6.压缩区段
	// 若存在tls，则不进行压缩
	if(pSelect->bIsCompression)
	if(!pPeInfo->bTls)
	pObjectPE->CompressSection(pPeInfo, pSelect);



}


//////////////////////////////////////////////////////////////////////////
//	植入Shell到宿主程序的新区段中
//	参数：
//	DWORD			dwFileBufSize			缓冲区长度
//	COperationPE*	pObjectPE				宿主程序的PE操作类指针
//	PEInfo			stcPeInfo				宿主程序的PE关键信息
//	PSHELL_DATA		pGlobalVar				传递给Shell的全局变量结构体指针
//////////////////////////////////////////////////////////////////////////

DWORD	Implantation(
	LPWSTR pFileName,
	DWORD dwFileBufSize,
	COperationPE* pObjectPE, 
	PEInfo stcPeInfo, 
	PSHELL_DATA pGlobalVar,
	PSelectionInfo pSelect)
{
	// 1. 在资源中读取文件内容
	HRSRC   hREC = NULL; // 资源对象
	HGLOBAL hREC_Handle = NULL; // 资源句柄
	DWORD   dwShellSize = NULL; // 文件大小
	LPVOID  pResData = NULL; // 资源数据指针
	HMODULE hModule = GetModuleHandle(L"SaerPackBase.dll");
	WCHAR*	szDirPath = new WCHAR[MAX_PATH];
	HANDLE	hFile;
	HMODULE	hMod;
	DWORD	dwBytesOfWritten;
	DWORD	dwDllOEP;		//dll启动函数的OEP（在启动函数没有在预编译选项设置权为入口点才使用该方法）


	if (!(hREC = FindResource(hModule, MAKEINTRESOURCE(IDR_SHELL1), L"SHELL")))  return FALSE;
	if (!(hREC_Handle = LoadResource(hModule, hREC)))							 return FALSE;
	if (!(pResData = LockResource(hREC_Handle)))								 return FALSE;
	if (!(dwShellSize = SizeofResource(hModule, hREC)))							 return FALSE;


	//////////////////////////////////////////////////////////////////////////
	//	括起处为新添加的代码，如有BUG，从此处进行修改
	// 1.2 将资源的DLL释放为文件形式，并加载到内存中获取该启动函数的OEP

	GetModuleFileName(NULL, szDirPath, MAX_PATH);
	PathRemoveFileSpec(szDirPath);
	BOOL bRootDir = PathIsRoot(szDirPath);

	if (bRootDir)
	{//若是根目录，不用加反斜杠
		wcscat_s(szDirPath, MAX_PATH, L"Temp.dll");
	}
	else
	{
		wcscat_s(szDirPath, MAX_PATH, L"\\Temp.dll");
	}

	hFile = CreateFile(szDirPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == NULL)
		exit(0);

	WriteFile(hFile, pResData, dwShellSize, &dwBytesOfWritten, NULL);

	CloseHandle(hFile);

	hMod = LoadLibrary(szDirPath);

	PSHELL_DATA pTempShell = (PSHELL_DATA)GetProcAddress(hMod, "g_stcShellData");

	dwDllOEP = pTempShell->dwPEOEP - (DWORD)hMod;

	FreeLibrary(hMod);

	DeleteFile(szDirPath);

	//////////////////////////////////////////////////////////////////////////



	// 2. 提取Shell部分的关键信息
	COperationPE  stcShellPE;
	PEInfo        stcShellPeInfo;
	LPBYTE        pData = new BYTE[dwShellSize];


	// 2.1 将Stub复制到临时缓冲区，防止重复操作
	CopyMemory(pData, pResData, dwShellSize);
	// 2.2 获取Stub的PE信息
	stcShellPE.GetPEInfo(pData, dwShellSize, &stcShellPeInfo);

	// 2.3 算出代码段的相关信息（默认第一个区段为代码段）
	LPBYTE pCodeBuf			= (LPBYTE)(stcShellPeInfo.pSectionHeader->PointerToRawData + (DWORD)pData);
	DWORD dwCodeBufSize		= stcShellPeInfo.pSectionHeader->SizeOfRawData;
	DWORD dwCodeRealSize	= stcShellPeInfo.pSectionHeader->SizeOfRawData;

	//对齐dwCodeBufSize
	if (dwCodeBufSize % stcShellPeInfo.dwSectionAlign)
	{
		dwCodeBufSize = (dwCodeBufSize / stcShellPeInfo.dwSectionAlign + 1) * stcShellPeInfo.dwSectionAlign;
	}
	else
	{
		dwCodeBufSize = (dwCodeBufSize / stcShellPeInfo.dwSectionAlign ) * stcShellPeInfo.dwSectionAlign;
	}


	//2.4  处理重定位段的相关信息
	DWORD	dwRelocSize;
	LPBYTE	pRelocBuf = stcShellPE.RVAToOffset(stcShellPeInfo.stcPERelocDir.VirtualAddress)  + pData;
	dwRelocSize = stcShellPeInfo.stcPERelocDir.Size;

	if (stcShellPeInfo.stcPERelocDir.Size % stcShellPeInfo.dwSectionAlign)
	{
		dwRelocSize = (dwRelocSize / stcShellPeInfo.dwSectionAlign + 1) * stcShellPeInfo.dwSectionAlign;
	}
	else
	{
		dwRelocSize = (dwRelocSize / stcShellPeInfo.dwSectionAlign ) * stcShellPeInfo.dwSectionAlign;
	}

	// 2.5 处理tls段的相关信息
	DWORD	dwTlsSectionStartRVA;
	DWORD	dwTlsSize				= 0;
	LPBYTE	pTlsBuf					= NULL;
	if (stcPeInfo.stcPETlsDir.VirtualAddress)
	{//判断是否存在tls表	


		//先找到tls段的起始位置

		stcShellPE.FindSectionOfTls(&stcShellPeInfo, &dwTlsSectionStartRVA, &dwTlsSize);

		pTlsBuf = stcShellPE.RVAToOffset(dwTlsSectionStartRVA) + pData;
		
		if (dwTlsSize % stcShellPeInfo.dwSectionAlign)
		{
			dwTlsSize = (dwTlsSize / stcShellPeInfo.dwSectionAlign + 1) * stcShellPeInfo.dwSectionAlign;
		}
		else
		{
			dwTlsSize = (dwTlsSize / stcShellPeInfo.dwSectionAlign) * stcShellPeInfo.dwSectionAlign;
		}

		pGlobalVar->bTlsExist = TRUE;

	}
	else
	{
		pGlobalVar->bTlsExist = FALSE;
	}


	// 2.6 处理idata段信息
	PIMAGE_SECTION_HEADER	pSecondSectionHeader = (stcShellPeInfo.pSectionHeader + 1);
	DWORD					dwDataSectionSize = pSecondSectionHeader->Misc.VirtualSize;
	DWORD					dwDataSectionRealSize = pSecondSectionHeader->Misc.VirtualSize;
	LPBYTE					pDataBuf = pSecondSectionHeader->PointerToRawData + pData;

	if (dwDataSectionSize % stcShellPeInfo.dwSectionAlign)
	{
		dwDataSectionSize = (dwDataSectionSize / stcShellPeInfo.dwSectionAlign + 1) * stcShellPeInfo.dwSectionAlign;
	}
	else
	{
		dwDataSectionSize = (dwDataSectionSize / stcShellPeInfo.dwSectionAlign) * stcShellPeInfo.dwSectionAlign;
	}
	

	//注意，由于目前shell没有导入表，所以idata段不存在，就不做处理!!!!!!!
	dwDataSectionSize = dwDataSectionRealSize = 0;


	// 2.7 将原IAT信息保存至shell的全局变量中
	pGlobalVar->dwIATSectionBase = stcPeInfo.dwOrigIATBase;
	pGlobalVar->dwIATSectionSize = stcPeInfo.dwOrigIATSize;



	// 2.8 处理宿主程序dll导出表，如果有的话
	DWORD	dwExportTableSize	= 0;
	LPBYTE	pExportBuf			= NULL;
	if (stcPeInfo.bIsDll)
	{
		dwExportTableSize	= stcPeInfo.pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		pExportBuf			= stcPeInfo.pExportBuf;
	}


	// 2.9 保存宿主程序旧的节表，以便解压时恢复区段信息,并将压缩区段的关键信息保存
	DWORD	dwCompressInfoSize = 0;
	DWORD	dwOriginalSecTableSize = 0;
	if (pSelect->bIsCompression)
	{
		if (!stcPeInfo.bTls)
		{
			dwCompressInfoSize = stcPeInfo.dwNumOfSections * sizeof(ComPressInfo);
			dwOriginalSecTableSize = stcPeInfo.dwNumOfSections * sizeof(IMAGE_SECTION_HEADER);
		}
	}
	

	// 2.10 将转储后的IAT表保存
	DWORD	dwNewIATSize = stcPeInfo.dwNewIATSize;
	

	// 2.11 将转储后的重定位表保存
	DWORD	dwNewRelocSize = stcPeInfo.dwNewRelocSize;

	// 3. 添加区段
	DWORD	dwNewSectionRawSize		= 0;		//pack2段的rawsize
	DWORD	dwNewSectionRealSize	= 0;		//pack2段的真实大小
	IMAGE_SECTION_HEADER  stcNewSection = { 0 };


	dwNewSectionRealSize = dwRelocSize + dwCodeBufSize + dwTlsSize + dwDataSectionSize + dwExportTableSize + dwOriginalSecTableSize +
							dwCompressInfoSize + dwNewIATSize + dwNewRelocSize;


	LPBYTE pNewSectionData = pObjectPE->AddSection(L".pack2", dwNewSectionRealSize,
		IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE, 
		&stcNewSection, &dwNewSectionRawSize);


	// 4. 对Stub部分进行的重定位操作
	//    新的加载地址 = (新区段的起始RVA - Shell的".Text"区段的起始RVA) + 映像基址
	DWORD dwLoadImageAddr = (stcNewSection.VirtualAddress - stcShellPeInfo.pSectionHeader->VirtualAddress) + stcPeInfo.dwImageBase;
	stcShellPE.RECReloc(dwLoadImageAddr, &stcNewSection);

	// 4.1 由于tls的特殊性，将模板数据始止地址及索引地址修正回来
	if (pGlobalVar->bTlsExist)
	{
		//覆盖其shell的tls数据
		stcShellPE.ChangeModuleData(stcPeInfo.dwTlsModStart, stcPeInfo.dwTlsModEnd, stcPeInfo.dwTlsIndexValue);
	}

	// 5. 写入配置参数
	// 5.1 获取Shell的导出变量地址

	PSHELL_DATA pShellGlobalVarAddr;
	CHAR		szDllName[MAX_PATH] = { 0 };

	//将模块的名字从Unicode转换为多字节
	WideCharToMultiByte(CP_ACP, NULL, pFileName, -1, szDllName, _countof(szDllName), NULL, FALSE);
	CopyMemory(pGlobalVar->szDllName, szDllName, strlen(szDllName));
	pShellGlobalVarAddr = (PSHELL_DATA)stcShellPE.GetExpVarAddr(L"g_stcShellData");

	if (pGlobalVar->bTlsExist)
	{
		pGlobalVar->stcPETlsShellDir.VirtualAddress = stcShellPeInfo.stcPETlsDir.VirtualAddress - stcShellPeInfo.pSectionHeader->VirtualAddress + stcNewSection.VirtualAddress;
		pGlobalVar->stcPETlsShellDir.Size = stcShellPeInfo.stcPETlsDir.Size;
	}

	if (stcPeInfo.bIsDll)
	{
		pGlobalVar->bDll = TRUE;
	}
	else
	{
		pGlobalVar->bDll = FALSE;
	}
	
	// 5.2 保存节表和压缩结构体的RVA
	pGlobalVar->dwOriginalSecRva	= pObjectPE->OffsetToRVA(stcNewSection.PointerToRawData + dwRelocSize + dwCodeBufSize + dwTlsSize + dwDataSectionSize + dwExportTableSize);
	pGlobalVar->dwCompressInfoRva	= pObjectPE->OffsetToRVA(stcNewSection.PointerToRawData + dwRelocSize + dwCodeBufSize + dwTlsSize + dwDataSectionSize + dwExportTableSize + dwOriginalSecTableSize);
	pGlobalVar->dwNewIATRva			= pObjectPE->OffsetToRVA(stcNewSection.PointerToRawData + dwRelocSize + dwCodeBufSize + dwTlsSize + dwDataSectionSize + dwExportTableSize + dwOriginalSecTableSize +
										dwCompressInfoSize);
	pGlobalVar->dwNewRelocRva		= pObjectPE->OffsetToRVA(stcNewSection.PointerToRawData + dwRelocSize + dwCodeBufSize + dwTlsSize + dwDataSectionSize + dwExportTableSize + dwOriginalSecTableSize +
										dwCompressInfoSize + dwNewIATSize);

	// 5.3 保存代码段的CRC32值
	pGlobalVar->dwCodeMemCRC32		= stcPeInfo.dwCodeMemCRC32;

	CopyMemory(pShellGlobalVarAddr, pGlobalVar, sizeof(SHELL_DATA));



	// 6. 将Shell复制到新区段中

	LPBYTE	pCombinedBuf = new BYTE[dwNewSectionRawSize];
	DWORD	dwCombinedOffset = 0;
	memset(pCombinedBuf, 0x0, dwNewSectionRawSize);

	// 6.1 复制代码段
	//此处最好是把code段的真实大小写进入，不要用对齐后的大小，可能会导致访问越界崩溃
	CopyMemory(pCombinedBuf + dwCombinedOffset, pCodeBuf, dwCodeRealSize);
	dwCombinedOffset += dwCodeBufSize;

	// 6.2 复制idata段
	//此处最好是把idata段的真实大小写进入，不要用对齐后的大小，可能会导致访问越界崩溃
	//CopyMemory(pCombinedBuf + dwCombinedOffset, pDataBuf, dwDataSectionRealSize);
	//dwCombinedOffset += dwDataSectionSize;
	
	// 6.3 复制tls段
	if (pGlobalVar->bTlsExist)
	{//若tls存在的话
		CopyMemory(pCombinedBuf + dwCombinedOffset, pTlsBuf, dwTlsSize);
		dwCombinedOffset += dwTlsSize;
	}
	

	// 6.4 复制重定位段
	//此处最好是把重定位段的真实大小写进入，不要用对齐后的大小，可能会导致访问越界崩溃
	CopyMemory(pCombinedBuf + dwCombinedOffset, pRelocBuf, stcShellPeInfo.stcPERelocDir.Size);
	dwCombinedOffset += dwRelocSize;


	// 6.5 复制导出表
	if (stcPeInfo.bIsDll)
	{
		//重定位导出表
		pObjectPE->RelocExportTable(pObjectPE->OffsetToRVA(stcNewSection.PointerToRawData + dwCodeBufSize + dwTlsSize + dwDataSectionSize + dwRelocSize),
			(PIMAGE_EXPORT_DIRECTORY)pExportBuf);

		CopyMemory(pCombinedBuf + dwCombinedOffset, pExportBuf, dwExportTableSize);
		dwCombinedOffset += dwExportTableSize;
	}

	// 6.6 将压缩数据和节表复制到shell的空间中
	if (pSelect->bIsCompression)
	if (!stcPeInfo.bTls)
	{
		// 6复制宿主程序的节表
		CopyMemory(pCombinedBuf + dwCombinedOffset, stcPeInfo.pOriginalSecTable, dwOriginalSecTableSize);
		dwCombinedOffset += dwOriginalSecTableSize;

		// 复制宿主程序的压缩区段结构
		
		CopyMemory(pCombinedBuf + dwCombinedOffset, stcPeInfo.pCompressInfo, dwCompressInfoSize);
		dwCombinedOffset += dwCompressInfoSize;
		
	}

	// 6.7复制转储后的IAT表
	if (pSelect->bIsTransferIAT)
	{
		CopyMemory(pCombinedBuf + dwCombinedOffset, stcPeInfo.pNewIATAddr, dwNewIATSize);
		dwCombinedOffset += dwNewIATSize;
	}

	// 6.8复制转储后的重定位表
	if (pSelect->bIsTransferReloc)
	{
		CopyMemory(pCombinedBuf + dwCombinedOffset, stcPeInfo.pNewRelocAddr, dwNewRelocSize);
		dwCombinedOffset += dwNewRelocSize;
	}



	//将区段缓冲区数据转移至新区段空间
	//dwCombinedOffset相当于整个区段的大小
	CopyMemory(pNewSectionData, pCombinedBuf, dwCombinedOffset);




	// 7. 修复资源表
	// 对宿主程序的要转移
	// 对资源表的存在做判断处理
	DWORD	dwNewResSectionSize = 0;
	if (stcPeInfo.stcPEResDir.Size != 0)
	dwNewResSectionSize = pObjectPE->FixRes(pObjectPE, &stcPeInfo);


	// 8. 计算并设置新OEP
	DWORD	dwNewOEP = 0;
	DWORD	dwShellOEP;
	//dwShellOEP = stcShellPeInfo.dwOEP;		//shell在dll中的OEP
	dwShellOEP = dwDllOEP;

	// 8.1 计算新OEP
	DWORD dwShellCodeRVA	= stcShellPeInfo.pSectionHeader->VirtualAddress;
	DWORD dwNewSectionRVA	= stcNewSection.VirtualAddress;

	dwNewOEP = (dwShellOEP - dwShellCodeRVA) + dwNewSectionRVA;

	// 8.2 设置新OEP
	pObjectPE->SetOEP(dwNewOEP);

	// 8.3 设置宿主程序的重定位表数据目录项
	pObjectPE->SetDir(IMAGE_DIRECTORY_ENTRY_BASERELOC,
		pObjectPE->OffsetToRVA(stcNewSection.PointerToRawData + dwCodeBufSize + dwTlsSize + dwDataSectionSize),
		stcShellPeInfo.stcPERelocDir.Size);

	// 8.4 设置宿主程序的tls表数据目录项
	if (pGlobalVar->bTlsExist)
	{
		pObjectPE->SetDir(IMAGE_DIRECTORY_ENTRY_TLS,
			stcShellPeInfo.stcPETlsDir.VirtualAddress - stcShellPeInfo.pSectionHeader->VirtualAddress + stcNewSection.VirtualAddress,
			stcShellPeInfo.stcPETlsDir.Size);
	}

	// 8.5 设置宿主程序的导出表数据目录项
	if (stcPeInfo.bIsDll)
	{
		pObjectPE->SetDir(IMAGE_DIRECTORY_ENTRY_EXPORT,
			pObjectPE->OffsetToRVA(stcNewSection.PointerToRawData +\
				dwCodeBufSize + dwTlsSize + dwDataSectionSize + dwRelocSize),
			stcPeInfo.pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
	}


	// 9. 释放资源，函数返回
	delete[] pData;
	delete[] pCombinedBuf;
	FreeResource(hREC_Handle);
	return dwNewSectionRawSize + dwNewResSectionSize;


}
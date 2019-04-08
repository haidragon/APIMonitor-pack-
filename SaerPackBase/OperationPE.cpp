#include "stdafx.h"
#include "OperationPE.h"


COperationPE::COperationPE()
{
	ZeroMemory(&m_stcPeInfo, sizeof(PEInfo));
}


COperationPE::~COperationPE()
{
}


DWORD COperationPE::RVAToOffset(DWORD dwRVA)
{
	PIMAGE_SECTION_HEADER	pSectionHeader		= IMAGE_FIRST_SECTION(m_pNtHeader);
	DWORD					dwNumberOfSections	= m_pNtHeader->FileHeader.NumberOfSections;

	for (DWORD i = 0; i < dwNumberOfSections ; i++ ,pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= dwRVA && dwRVA < pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress)
		{
			return	dwRVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}

	return	NULL;
}


DWORD	COperationPE::OffsetToRVA(DWORD dwRawPointer)
{
	PIMAGE_SECTION_HEADER	pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	DWORD					dwNumberOfSections = m_pNtHeader->FileHeader.NumberOfSections;

	for (DWORD i = 0; i < dwNumberOfSections; i++, pSectionHeader++)
	{
		if (pSectionHeader->PointerToRawData <= dwRawPointer && 
			dwRawPointer < pSectionHeader->SizeOfRawData + pSectionHeader->PointerToRawData)
		{
			return	dwRawPointer - pSectionHeader->PointerToRawData + pSectionHeader->VirtualAddress;
		}
	}

	return	NULL;
}


//////////////////////////////////////////////////////////////////////////
//	获取当前程序的文件指针
//	返回值：
//	DWORD 文件指针
//////////////////////////////////////////////////////////////////////////

DWORD	COperationPE::GetFileAddr()
{
	return m_dwFileDataAddr;
}

//////////////////////////////////////////////////////////////////////////
//	获取当前程序的文件大小
//	返回值：
//	DWORD 文件大小
//////////////////////////////////////////////////////////////////////////
DWORD	COperationPE::GetFileRawSize()
{
	return m_dwFileDataSize;
}


//////////////////////////////////////////////////////////////////////////
//	获取pFileBuf缓冲区中的关键PE信息
//	参数：
//	LPBYTE pFileBuf			目标程序的缓冲区,必须是个完整的PE文件映射的缓冲区
//	DWORD dwFileSize		目标程序的文件大小（按FileAlign对齐）
//	pPEInfo pObjectPEInfo	[out]目标文件的关键信息结构体
//////////////////////////////////////////////////////////////////////////

BOOL COperationPE::GetPEInfo(LPBYTE pFileBuf, DWORD dwFileSize, pPEInfo pObjectPEInfo)
{

	if (m_stcPeInfo.dwOEP)
	{
		//恢复第一个区段,因为之前会对textbss做处理
		pObjectPEInfo->pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
		//更新区段数量，代码乱序后需要该处理
		pObjectPEInfo->dwNumOfSections = m_pNtHeader->FileHeader.NumberOfSections;
		memcpy_s(&m_stcPeInfo, sizeof(PEInfo), pObjectPEInfo, sizeof(PEInfo));
		return	TRUE;
	}
	else
	{
		if (!pFileBuf)
			return FALSE;
		m_dwFileDataAddr = (DWORD)pFileBuf;
		m_dwFileDataSize = (DWORD)dwFileSize;
	}




	m_pDosHeader	= (PIMAGE_DOS_HEADER)pFileBuf;
	m_pNtHeader		= (PIMAGE_NT_HEADERS)(m_pDosHeader->e_lfanew + pFileBuf);
	m_bCRC32Table	= FALSE;
	pObjectPEInfo->dwOEP				= m_pNtHeader->OptionalHeader.AddressOfEntryPoint;
	pObjectPEInfo->dwImageBase			= m_pNtHeader->OptionalHeader.ImageBase;
	pObjectPEInfo->dwSizeOfImage		= m_pNtHeader->OptionalHeader.SizeOfImage;
	pObjectPEInfo->pDataDir				= m_pNtHeader->OptionalHeader.DataDirectory;
	pObjectPEInfo->dwNumOfSections		= m_pNtHeader->FileHeader.NumberOfSections;
	pObjectPEInfo->pSectionHeader		= IMAGE_FIRST_SECTION(m_pNtHeader);
	pObjectPEInfo->stcPEImportDir		= IMAGE_DATA_DIRECTORY(pObjectPEInfo->pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	pObjectPEInfo->stcPERelocDir		= IMAGE_DATA_DIRECTORY(pObjectPEInfo->pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	pObjectPEInfo->stcPEResDir			= IMAGE_DATA_DIRECTORY(pObjectPEInfo->pDataDir[IMAGE_DIRECTORY_ENTRY_RESOURCE]);
	pObjectPEInfo->stcPETlsDir			= IMAGE_DATA_DIRECTORY(pObjectPEInfo->pDataDir[IMAGE_DIRECTORY_ENTRY_TLS]);
	pObjectPEInfo->stcIATDir			= IMAGE_DATA_DIRECTORY(pObjectPEInfo->pDataDir[IMAGE_DIRECTORY_ENTRY_IAT]);
	pObjectPEInfo->dwSectionAlign		= m_pNtHeader->OptionalHeader.SectionAlignment;
	pObjectPEInfo->dwFileAlign			= m_pNtHeader->OptionalHeader.FileAlignment;
	pObjectPEInfo->dwTlsOffset			= 0;
	pObjectPEInfo->dwTlsSectionRVA		= 0;
	pObjectPEInfo->dwSizeOfHeader		= m_pNtHeader->OptionalHeader.SizeOfHeaders;
	pObjectPEInfo->pExpAddrOfName		= NULL;
	pObjectPEInfo->pOriginalSecTable	= NULL;
	pObjectPEInfo->dwOrigIATBase		= NULL;
	pObjectPEInfo->dwOrigIATSize		= NULL;
	pObjectPEInfo->pNewIATAddr			= NULL;
	pObjectPEInfo->dwNewIATSize			= NULL;
	pObjectPEInfo->pNewRelocAddr		= NULL;
	pObjectPEInfo->dwNewRelocSize		= NULL;
	pObjectPEInfo->dwCodeMemCRC32		= NULL;
	pObjectPEInfo->dwCodeBase			= NULL;
	pObjectPEInfo->dwCodeSize			= 0;
	pObjectPEInfo->dwCodeRawSize		= 0;


	if ((m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) || (m_pNtHeader->Signature != IMAGE_NT_SIGNATURE))
	{
		// 这不是一个有效的PE文件
		return FALSE;
	}

	if (m_pNtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64 ||
		m_pNtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		MessageBox(NULL, L"不支持x64程序的加壳操作！", L"错误", NULL);
		exit(0);
	}



	if ((m_pNtHeader->FileHeader.Characteristics & 0x2000) == IMAGE_FILE_DLL)
	{//判断是否为dll文件
		pObjectPEInfo->bIsDll = TRUE;
	}
	else
	{
		pObjectPEInfo->bIsDll = FALSE;
	}

	if (pObjectPEInfo->stcPETlsDir.VirtualAddress != 0)
	{//判断是否有tls段
		pObjectPEInfo->bTls = TRUE;
	}
	else
	{
		pObjectPEInfo->bTls = FALSE;
	}


	memcpy_s(&m_stcPeInfo, sizeof(PEInfo), pObjectPEInfo, sizeof(PEInfo));

	return TRUE;
}


//////////////////////////////////////////////////////////////////////////
//	重定位自身，只能是Shell的COperationPE类才能用，修改Shell缓冲区中的重定位项,
//	对tls表进行特殊处理
//	参数：
//	DWORD					dwLoadImageBase			新的区段RVA（宿主程序操作类的成员）- Shell的"Text"RVA + 宿主程序ImageBase
//	PIMAGE_SECTION_HEADER	pObjectPeNewSection		宿主程序的新区段头结构体
//////////////////////////////////////////////////////////////////////////

VOID COperationPE::RECReloc(DWORD dwLoadImageBase, PIMAGE_SECTION_HEADER	pObjectPeNewSection)
{
	typedef struct _TYPEOFFSET
	{
		WORD offset : 12;			//偏移值
		WORD Type : 4;			//重定位属性(方式)
	}TYPEOFFSET, *PTYPEOFFSET;

	PIMAGE_BASE_RELOCATION	pReloc = (PIMAGE_BASE_RELOCATION)(m_dwFileDataAddr + RVAToOffset(m_stcPeInfo.stcPERelocDir.VirtualAddress));
	DWORD					dwRelocOfItemNum;
	DWORD					dwRVA;
	DWORD					dwItemAddressOfReloc;
	DWORD					dwTestAddr;
	PTYPEOFFSET				pOffset;
	DWORD					dwTestRVA;
	DWORD					dwEndOfReloc = (DWORD)pReloc + m_stcPeInfo.stcPERelocDir.Size;

	while (pReloc->VirtualAddress)
	{
	
		pOffset = (PTYPEOFFSET)((DWORD)pReloc + sizeof(IMAGE_BASE_RELOCATION));

		dwRelocOfItemNum = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

		for (DWORD i = 0; i < dwRelocOfItemNum; i++, pOffset++)
		{

		
			if (pOffset->Type  != IMAGE_REL_BASED_HIGHLOW)
			continue;



			dwRVA = pReloc->VirtualAddress + pOffset->offset;

			*(DWORD*)(RVAToOffset(dwRVA) + (DWORD)m_dwFileDataAddr) +=( dwLoadImageBase - m_stcPeInfo.dwImageBase);
			dwTestRVA  = RVAToOffset(dwRVA);
			dwTestAddr = RVAToOffset(dwRVA) + (DWORD)m_dwFileDataAddr;
			dwItemAddressOfReloc = *(DWORD*)(RVAToOffset(dwRVA) + (DWORD)m_dwFileDataAddr);//测试用

		}

		//新区段RVA + dwAlignBlock * SectionAlign
	/*	pReloc->VirtualAddress = dwAlignBlock * m_pNtHeader->OptionalHeader.SectionAlignment + pObjectPeNewSection->VirtualAddress;*/

		//因为shell没有textbss段，直接减去0x1000就好啦
		pReloc->VirtualAddress = pReloc->VirtualAddress - 0x1000 + pObjectPeNewSection->VirtualAddress;

		if (dwEndOfReloc == (DWORD)pOffset)
			return;

		pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pReloc + pReloc->SizeOfBlock);

	


	}

}


//////////////////////////////////////////////////////////////////////////
//	以FOA方式获取全局变量的地址
//	参数：
//	LPCTSTR strVarName		与当前字符集相同类型的字符串，全局变量的名字
//////////////////////////////////////////////////////////////////////////

LPBYTE COperationPE::GetExpVarAddr(LPWSTR strVarName)
{
	// 1、获取导出表地址，并将参数strVarName转为ASCII形式，方便对比查找
	PCHAR strTempName;
	PDWORD pNameAddr;
	PDWORD pFunAddr;
	CHAR szVarName[MAX_PATH] = { 0 };
	IMAGE_DATA_DIRECTORY	stcExport;
	stcExport = IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	PIMAGE_EXPORT_DIRECTORY lpExport = (PIMAGE_EXPORT_DIRECTORY)(m_dwFileDataAddr + RVAToOffset(stcExport.VirtualAddress));
	WideCharToMultiByte(CP_ACP, NULL, strVarName, -1, szVarName, _countof(szVarName), NULL, FALSE);

	// 2、循环读取导出表输出项的输出函数，并依次与szVarName做比对，如果相同，则取出相对应的函数地址
	for (DWORD i = 0; i < lpExport->NumberOfNames; i++)
	{
		 pNameAddr = (PDWORD)(m_dwFileDataAddr + RVAToOffset(lpExport->AddressOfNames + i));
		 strTempName = (PCHAR)(m_dwFileDataAddr + RVAToOffset(*pNameAddr));

		if (!strcmp(szVarName, strTempName))
		{
			pFunAddr = (PDWORD)(m_dwFileDataAddr + RVAToOffset(lpExport->AddressOfFunctions + i));
			return (LPBYTE)(m_dwFileDataAddr + RVAToOffset(*pFunAddr));
		}
	}
	return 0;
}


//////////////////////////////////////////////////////////////////////////
//				添加一个新的区段
//	参数：
//	LPCTSTR strName						区段名字
//	DWORD dwSize						该区段的实际尺寸
//	DWORD dwCharac						区段的属性
//	PIMAGE_SECTION_HEADER pNewSection	[out]新区段的头结构
//	PDWORD pSizeOfRaw					[out]新区段的SizeOfRawData
//	返回值								区段的真实地址，便于后面写入数据
//////////////////////////////////////////////////////////////////////////

LPBYTE COperationPE::AddSection(LPWSTR strName, DWORD dwSize, DWORD dwCharac, PIMAGE_SECTION_HEADER pNewSection, PDWORD pSizeOfRaw)
{
	DWORD	dwDosSize			= m_pDosHeader->e_lfanew;
	DWORD	dwPeSize			= sizeof(m_pNtHeader->Signature) + m_pNtHeader->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER);
	DWORD	dwNumOfSections		= m_pNtHeader->FileHeader.NumberOfSections;
	DWORD	dwSectionTableSize  = dwNumOfSections * sizeof(IMAGE_SECTION_HEADER);
	DWORD	dwFileAlign			= m_pNtHeader->OptionalHeader.FileAlignment;
	DWORD	dwSectionAlign		= m_pNtHeader->OptionalHeader.SectionAlignment;
	CHAR	szVarName[8] = { 0 };
	IMAGE_SECTION_HEADER	stcLastSectionHeader = 	m_stcPeInfo.pSectionHeader[dwNumOfSections - 1];
	IMAGE_SECTION_HEADER	stcNewSectionHeader;
	DWORD	dwNewSectionVirtualAddress;
	DWORD	dwNewSectionPointerToRaw;
	DWORD	dwNewSectionVirtualSize;
	DWORD	dwNewSectionRawSize;

	if (dwSize % dwSectionAlign)
	{
		dwNewSectionVirtualSize = (dwSize / dwSectionAlign + 1) * dwSectionAlign;
	}
	else
	{
		dwNewSectionVirtualSize = (dwSize / dwSectionAlign) * dwSectionAlign;
	}

	if (dwSize % dwFileAlign)
	{
		dwNewSectionRawSize = (dwSize / dwFileAlign + 1) * dwFileAlign;
	}
	else
	{
		dwNewSectionRawSize = (dwSize / dwFileAlign ) * dwFileAlign;
	}

	*pSizeOfRaw = dwNewSectionRawSize;
	dwNewSectionPointerToRaw	= stcLastSectionHeader.PointerToRawData + stcLastSectionHeader.SizeOfRawData;


	if (stcLastSectionHeader.Misc.VirtualSize % dwSectionAlign)
	{
		dwNewSectionVirtualAddress = (stcLastSectionHeader.Misc.VirtualSize / dwSectionAlign + 1) * dwSectionAlign + stcLastSectionHeader.VirtualAddress;

	}
	else
	{
		dwNewSectionVirtualAddress = (stcLastSectionHeader.Misc.VirtualSize / dwSectionAlign ) * dwSectionAlign + stcLastSectionHeader.VirtualAddress;
	}


	WideCharToMultiByte(CP_ACP, NULL, strName, -1, szVarName, _countof(szVarName), NULL, FALSE);
	memset(&stcNewSectionHeader, 0x0, sizeof(IMAGE_SECTION_HEADER));
	memcpy_s(stcNewSectionHeader.Name, 8, szVarName, strlen(szVarName));
	stcNewSectionHeader.Misc.VirtualSize	 = dwNewSectionVirtualSize;
	stcNewSectionHeader.VirtualAddress		 = dwNewSectionVirtualAddress;
	stcNewSectionHeader.SizeOfRawData		 = dwNewSectionRawSize;
	stcNewSectionHeader.PointerToRawData	 = dwNewSectionPointerToRaw;
	stcNewSectionHeader.Characteristics		 = dwCharac;
	memcpy_s(&m_stcPeInfo.pSectionHeader[dwNumOfSections], sizeof(IMAGE_SECTION_HEADER),
	&stcNewSectionHeader, sizeof(IMAGE_SECTION_HEADER));

	m_pNtHeader->OptionalHeader.SizeOfImage += dwNewSectionVirtualSize;

	m_pNtHeader->FileHeader.NumberOfSections++;

	memcpy_s(pNewSection, sizeof(IMAGE_SECTION_HEADER), &stcNewSectionHeader, sizeof(IMAGE_SECTION_HEADER));

	//更新文件RS
	m_dwFileDataSize += *pSizeOfRaw;

	return	(LPBYTE)(m_dwFileDataAddr + dwNewSectionPointerToRaw);

}

//////////////////////////////////////////////////////////////////////////
//	设置新的OEP
//	参数：
//	DWORD dwOEP			新的入口点		
//////////////////////////////////////////////////////////////////////////

VOID COperationPE::SetOEP(DWORD dwOEP)
{
	m_pNtHeader->OptionalHeader.AddressOfEntryPoint = dwOEP;
}



//////////////////////////////////////////////////////////////////////////
//	在数据目录项中清除不需要的项，保留资源表、重定位表、导出表
//////////////////////////////////////////////////////////////////////////

VOID COperationPE::CleanDir()
{
	DWORD dwCount = 15;
	for (DWORD i = 0; i < dwCount; i++)
	{
		if (i != IMAGE_DIRECTORY_ENTRY_EXPORT &&
			i != IMAGE_DIRECTORY_ENTRY_RESOURCE &&
			i != IMAGE_DIRECTORY_ENTRY_BASERELOC&&
			i != IMAGE_DIRECTORY_ENTRY_TLS)
		{
			m_pNtHeader->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
			m_pNtHeader->OptionalHeader.DataDirectory[i].Size = 0;
		}
	}
}



VOID COperationPE::FindSectionOfIAT(PDWORD dwIATBase, PDWORD dwSize)
{
	PIMAGE_SECTION_HEADER	pFirstSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	DWORD					dwNumOfSections		= m_pNtHeader->FileHeader.NumberOfSections;


	for (DWORD i = 0;
		i < dwNumOfSections;
		i++, pFirstSectionHeader++)
	{
		if (m_stcPeInfo.stcPEImportDir.VirtualAddress >= pFirstSectionHeader->VirtualAddress &&
			m_stcPeInfo.stcPEImportDir.VirtualAddress < pFirstSectionHeader->VirtualAddress + pFirstSectionHeader->Misc.VirtualSize)
		{
			*dwIATBase = pFirstSectionHeader->VirtualAddress;
			*dwSize = pFirstSectionHeader->Misc.VirtualSize;
			break;
		}

	}

}


//////////////////////////////////////////////////////////////////////////
//	提取资源目录头和关键数据合并在一个缓冲区中
//	缓冲区中先是存在资源头，接着连接关键数据
//	（注：指向缓冲区的变量存放在PEInfo结构当中）	
//	参数：
//	pPEInfo pObjectPE					//宿主程序的PE结构指针
//  BUG: 忘记对没有资源表的程序做判断处理
//////////////////////////////////////////////////////////////////////////

VOID	COperationPE::ReBuildRes(pPEInfo pObjectPE)
{
	IMAGE_DATA_DIRECTORY	stcResDir = IMAGE_DATA_DIRECTORY(pObjectPE->pDataDir[IMAGE_DIRECTORY_ENTRY_RESOURCE]);
	DWORD					dwResHeaderEndRVA;
	DWORD					dwResHeaderSize;
	DWORD					dwNewResOffset	= 0;
	LPBYTE					pNewResAddr;
	LPBYTE					pResStartAddr	= (LPBYTE)(m_dwFileDataAddr + RVAToOffset(stcResDir.VirtualAddress));

	pObjectPE->dwNewResSize = 0;

	dwResHeaderEndRVA = FindResourceHeader(pResStartAddr, pResStartAddr, pObjectPE->dwSizeOfImage);
	
	//资源头大小	= 资源头末址	-	资源头起始地址
	dwResHeaderSize = dwResHeaderEndRVA - stcResDir.VirtualAddress;
	
	pObjectPE->dwResHeaderSize = dwResHeaderSize;

	pObjectPE->dwNewResAddr = (DWORD)VirtualAlloc(NULL, stcResDir.Size * 2, MEM_COMMIT, PAGE_READWRITE);
	
	pNewResAddr				= (LPBYTE)pObjectPE->dwNewResAddr;

	ZeroMemory((PVOID)pNewResAddr, stcResDir.Size * 2);

	CopyMemory((PVOID)pNewResAddr,
				(PVOID)pResStartAddr,
				dwResHeaderSize);
	pObjectPE->dwNewResSize += dwResHeaderSize;

	pNewResAddr += dwResHeaderSize;


	//读取图标 
	MoveObjectRes(pResStartAddr, (DWORD)RT_ICON, pNewResAddr, &dwNewResOffset);
	pObjectPE->dwNewResSize += dwNewResOffset;
	//读取图标组
	pNewResAddr += dwNewResOffset;
	MoveObjectRes(pResStartAddr, (DWORD)RT_GROUP_ICON, pNewResAddr, &dwNewResOffset);
	pObjectPE->dwNewResSize += dwNewResOffset;
	//读取版本信息
	pNewResAddr += dwNewResOffset;
	MoveObjectRes(pResStartAddr, (DWORD)RT_VERSION, pNewResAddr, &dwNewResOffset);
	pObjectPE->dwNewResSize += dwNewResOffset;

	//Manifest
	pNewResAddr += dwNewResOffset;
	MoveObjectRes(pResStartAddr, (DWORD)RT_MANIFEST, pNewResAddr, &dwNewResOffset);
	pObjectPE->dwNewResSize += dwNewResOffset;



}


//////////////////////////////////////////////////////////////////////////
//	找到资源目录头的末尾RVA
//	参数：
//	LPBYTE	pResHeaderAddr					资源头的地址
//	LPBYTE  pResAddr						当前资源目录的起始地址
//	DWORD	dwMinRVA						最大数据的RVA
//////////////////////////////////////////////////////////////////////////

DWORD	COperationPE::FindResourceHeader(LPBYTE pResHeaderAddr, LPBYTE pResAddr, DWORD	dwMinRVA)
{
	PIMAGE_RESOURCE_DIRECTORY		pResDir = (PIMAGE_RESOURCE_DIRECTORY)pResAddr;
	DWORD							dwNumOfID;
	DWORD							dwNumOfName;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pResDirEntry;
	PIMAGE_RESOURCE_DATA_ENTRY		pResDataEntry;
	DWORD							dwReturnedMinRVA;


	dwNumOfID = pResDir->NumberOfIdEntries;
	dwNumOfName = pResDir->NumberOfNamedEntries;


	pResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResDir + sizeof(IMAGE_RESOURCE_DIRECTORY));
	


	if (dwNumOfName)
	{
		for (DWORD i = 0; i < dwNumOfName ; i++)
		{
			if (pResDirEntry->DataIsDirectory)
			{
				dwReturnedMinRVA = FindResourceHeader(pResHeaderAddr,pResDirEntry->OffsetToDirectory + pResHeaderAddr, dwMinRVA);
				if (dwReturnedMinRVA < dwMinRVA)	dwMinRVA = dwReturnedMinRVA;

			}
			else
			{
				pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(pResDirEntry->OffsetToData + pResHeaderAddr);
				
				if (pResDataEntry->OffsetToData < dwMinRVA)	return pResDataEntry->OffsetToData;
				
			}//if

			pResDirEntry += 1;
		}//for
	}



	if (dwNumOfID)
	{
		for (DWORD i = 0; i < dwNumOfID; i++)
		{
			if (pResDirEntry->DataIsDirectory)
			{
				dwReturnedMinRVA =  FindResourceHeader(pResHeaderAddr,pResDirEntry->OffsetToDirectory + pResHeaderAddr, dwMinRVA);
				
				if (dwReturnedMinRVA < dwMinRVA)	dwMinRVA = dwReturnedMinRVA;

			}
			else
			{
				pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(pResDirEntry->OffsetToData + pResHeaderAddr);

				if (pResDataEntry->OffsetToData < dwMinRVA)	return pResDataEntry->OffsetToData;

			}//if

			pResDirEntry += 1;
		}//for
	}

	return	dwMinRVA;

}


//////////////////////////////////////////////////////////////////////////
//	找到指定类型的资源，将其写入给定的缓冲区中
//	参数：
//	LPBYTE pResAddr				资源段的ptr
//	DWORD  dwType				需要读取的指定类型
//	LPBYTE pDataBuf				写入的缓冲区
//	PDWORD dwBufSize			[out]写入的总大小
//////////////////////////////////////////////////////////////////////////

VOID	COperationPE::MoveObjectRes(LPBYTE pResAddr, DWORD dwType, LPBYTE pDataBuf, PDWORD dwBufSize)
{
	PIMAGE_RESOURCE_DIRECTORY		pResTypeDir = (PIMAGE_RESOURCE_DIRECTORY)pResAddr;
	PIMAGE_RESOURCE_DIRECTORY		pResNameIdDir;
	PIMAGE_RESOURCE_DIRECTORY		pResLanguageDir;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pResTypeDirEntry;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pResNameIdEntry;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pResLanguageEntry;
	PIMAGE_RESOURCE_DATA_ENTRY		pResDataEntry;
	DWORD							dwNumOfType		= 0;
	DWORD							dwNumOfNameId	= 0;
	DWORD							dwNumOfLanguage = 0;
	DWORD							dwWrittenBytes	= 0;
	LPBYTE							pTempBuf = NULL;

	dwNumOfType += pResTypeDir->NumberOfIdEntries;
	dwNumOfType += pResTypeDir->NumberOfNamedEntries;


	pResTypeDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResTypeDir + 1);

	for (DWORD dwTypeIndex = 0; dwTypeIndex < dwNumOfType; dwTypeIndex++, pResTypeDirEntry++)
	{//第一层目录结构

		if (!pResTypeDirEntry->NameIsString)
		{
			if (pResTypeDirEntry->Name == dwType)
			{
				pResNameIdDir = (PIMAGE_RESOURCE_DIRECTORY)(pResTypeDirEntry->OffsetToDirectory + pResAddr);

				pResNameIdEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResNameIdDir + 1);

				dwNumOfNameId = pResNameIdDir->NumberOfNamedEntries + pResNameIdDir->NumberOfIdEntries;

				for (DWORD dwNameIdIndex = 0; dwNameIdIndex < dwNumOfNameId; dwNameIdIndex++, pResNameIdEntry++)
				{//第二层目录结构
					//if (!pResNameIdEntry->NameIsString)
					//{
						pResLanguageDir = (PIMAGE_RESOURCE_DIRECTORY)(pResNameIdEntry->OffsetToDirectory + pResAddr);
						dwNumOfLanguage = pResLanguageDir->NumberOfNamedEntries + pResLanguageDir->NumberOfIdEntries;
						pResLanguageEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResLanguageDir + 1);

						for (DWORD dwLanguageIndex = 0; dwLanguageIndex < dwNumOfLanguage; dwLanguageIndex++, pResLanguageEntry++)
						{//第三层目录
							//if (!pResLanguageEntry->NameIsString)
							//{
								//读取资源数据
								
								pResDataEntry	= (PIMAGE_RESOURCE_DATA_ENTRY)(pResLanguageEntry->OffsetToData + pResAddr);

								pTempBuf		= (LPBYTE)RVAToOffset(pResDataEntry->OffsetToData) + m_dwFileDataAddr;

								CopyMemory(pDataBuf + dwWrittenBytes, pTempBuf, pResDataEntry->Size);

								//ZeroMemory(pTempBuf, pResDataEntry->Size);

								dwWrittenBytes += pResDataEntry->Size;

						//	}
						}
					//}
				}
			}
		}
	}

	*dwBufSize = dwWrittenBytes;

}

//////////////////////////////////////////////////////////////////////////
//	修复新资源段的偏移，只对资源头进行关键数据的修改，不改变资源数据
//	参数：
//	LPBYTE	pNewResAddr				存放新资源头的缓冲区的起始地址
//	DWORD	dwType					指定类型
//	DWORD	dwCurrentRVA			当前所有关键资源数据的起始RVA（作为计算公式的基址）
//	DWORD	dwDataOffset			当前偏移量
//	PDWORD	dwReturnedDataSize		[out]当前遍历的关键数据的大小
//////////////////////////////////////////////////////////////////////////

VOID	COperationPE::FixResDataEntry(LPBYTE pNewResAddr, DWORD dwType, DWORD dwCurrentRVA, DWORD dwDataOffset, PDWORD	dwReturnedDataSize)
{
	PIMAGE_RESOURCE_DIRECTORY		pResTypeDir = (PIMAGE_RESOURCE_DIRECTORY)pNewResAddr;
	PIMAGE_RESOURCE_DIRECTORY		pResNameIdDir;
	PIMAGE_RESOURCE_DIRECTORY		pResLanguageDir;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pResTypeDirEntry;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pResNameIdEntry;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pResLanguageEntry;
	PIMAGE_RESOURCE_DATA_ENTRY		pResDataEntry;
	DWORD							dwNumOfType = 0;
	DWORD							dwNumOfNameId = 0;
	DWORD							dwNumOfLanguage = 0;
	DWORD							dwWrittenBytes = 0;
	BOOL							bChanged = FALSE;

	dwNumOfType += pResTypeDir->NumberOfIdEntries;
	dwNumOfType += pResTypeDir->NumberOfNamedEntries;


	pResTypeDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResTypeDir + 1);

	for (DWORD dwTypeIndex = 0; dwTypeIndex < dwNumOfType; dwTypeIndex++, pResTypeDirEntry++)
	{//第一层目录结构

		if (!pResTypeDirEntry->NameIsString)
		{
			if (pResTypeDirEntry->Name == dwType)
			{
				pResNameIdDir = (PIMAGE_RESOURCE_DIRECTORY)(pResTypeDirEntry->OffsetToDirectory + pNewResAddr);

				pResNameIdEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResNameIdDir + 1);

				dwNumOfNameId = pResNameIdDir->NumberOfNamedEntries + pResNameIdDir->NumberOfIdEntries;

				for (DWORD dwNameIdIndex = 0; dwNameIdIndex < dwNumOfNameId; dwNameIdIndex++, pResNameIdEntry++)
				{//第二层目录结构
					//if (!pResNameIdEntry->NameIsString)
					//{
						pResLanguageDir = (PIMAGE_RESOURCE_DIRECTORY)(pResNameIdEntry->OffsetToDirectory + pNewResAddr);
						dwNumOfLanguage = pResLanguageDir->NumberOfNamedEntries + pResLanguageDir->NumberOfIdEntries;
						pResLanguageEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResLanguageDir + 1);

						for (DWORD dwLanguageIndex = 0; dwLanguageIndex < dwNumOfLanguage; dwLanguageIndex++, pResLanguageEntry++)
						{//第三层目录
							//if (!pResLanguageEntry->NameIsString)
							//{
							//读取资源数据

								pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(pResLanguageEntry->OffsetToData + pNewResAddr);

								//if (!bChanged)
							//	{//保证Data_Entry的资源数据RVA只修改一次
									pResDataEntry->OffsetToData = dwCurrentRVA + dwDataOffset;
									//bChanged = TRUE;
							//	}
								dwWrittenBytes += pResDataEntry->Size;
								dwDataOffset += pResDataEntry->Size;
							//}
						}
					//}
				}
			}
		}
	}

	*dwReturnedDataSize = dwWrittenBytes;

}


//////////////////////////////////////////////////////////////////////////
//	修复新资源段的关键数据，修复顺序：图标-》图标组-》版本信息
//	注意：若无关键资源类型，则该段只包含资源头
//	参数：
//	COperationPE*	pObjectPE			宿主程序的PE操作类
//	pPEInfo			pObjectPEInfo		宿主程序的PE关键信息结构体
//	返回值			新区段的大小
//////////////////////////////////////////////////////////////////////////



DWORD	COperationPE::FixRes(COperationPE* pObjectPE, pPEInfo pObjectPEInfo)
{
	// 1.添加新区段
	IMAGE_SECTION_HEADER	stcNewSectionHeader;
	DWORD					dwSizeOfRawData;
	DWORD					dwOffset		= 0;
	DWORD					dwReturnedSize	= 0;
	LPBYTE					pNewSectionAddr;

	pNewSectionAddr	= pObjectPE->AddSection(L".rsrc", pObjectPEInfo->dwNewResSize, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
		&stcNewSectionHeader, &dwSizeOfRawData);

	CopyMemory((PVOID)pNewSectionAddr, (PVOID)pObjectPEInfo->dwNewResAddr, pObjectPEInfo->dwNewResSize);



	// 2.按顺序修复三种类型的资源
	// 2.1 图标
	FixResDataEntry(pNewSectionAddr, (DWORD)RT_ICON, stcNewSectionHeader.VirtualAddress + pObjectPEInfo->dwResHeaderSize,
					dwOffset, &dwReturnedSize);

	// 2.2 图标组
	dwOffset += dwReturnedSize;
	FixResDataEntry(pNewSectionAddr, (DWORD)RT_GROUP_ICON, stcNewSectionHeader.VirtualAddress + pObjectPEInfo->dwResHeaderSize,
					dwOffset, &dwReturnedSize);

	// 2.3 版本信息
	dwOffset += dwReturnedSize;
	FixResDataEntry(pNewSectionAddr, (DWORD)RT_VERSION, stcNewSectionHeader.VirtualAddress + pObjectPEInfo->dwResHeaderSize,
		dwOffset, &dwReturnedSize);

	//2.5 Manifest
	dwOffset += dwReturnedSize;
	FixResDataEntry(pNewSectionAddr, (DWORD)RT_MANIFEST, stcNewSectionHeader.VirtualAddress + pObjectPEInfo->dwResHeaderSize,
		dwOffset, &dwReturnedSize);



	PIMAGE_DATA_DIRECTORY	pResDir = &(pObjectPE->m_stcPeInfo.pDataDir[IMAGE_DIRECTORY_ENTRY_RESOURCE]);


	//该处理针对不存在关键资源类型的情况下，dwOffset为0
	if (dwOffset)
	{
		pResDir->VirtualAddress = stcNewSectionHeader.VirtualAddress;
		pResDir->Size = pObjectPEInfo->dwNewResSize;
		
	}
	else
	{
		memset(pResDir, 0x0, sizeof(IMAGE_DATA_DIRECTORY));
	}

	return	dwSizeOfRawData;


}


//////////////////////////////////////////////////////////////////////////
//	求出tls段所在段的起始RVA和该段的真实大小
//	参数：
//	pPEInfo pObjectPEInfo								PE关键信息结构体
//	PDWORD	dwTlsSectionStartRVA						[out]tls段的起始RVA
//	PDWORD	dwSectionRealSize							[out]tls段的真实大小
//////////////////////////////////////////////////////////////////////////

BOOL	COperationPE::FindSectionOfTls(pPEInfo pObjectPEInfo, PDWORD dwTlsSectionStartRVA, PDWORD dwSectionRealSize)
{
	//要用PE关键结构中的，因为有些程序可能会有textbss作为第一个区段
	PIMAGE_SECTION_HEADER	pSectionHeader = pObjectPEInfo->pSectionHeader;
	DWORD					dwNumOfSections = m_pNtHeader->FileHeader.NumberOfSections;
	DWORD					dwCodeEndRVA;
	if (!pObjectPEInfo->stcPETlsDir.VirtualAddress)		return FALSE;
	

	//默认第一个区段为代码段
	if (pSectionHeader->Misc.VirtualSize % pObjectPEInfo->dwSectionAlign)
	{
		dwCodeEndRVA = (pSectionHeader->Misc.VirtualSize / pObjectPEInfo->dwSectionAlign + 1) * pObjectPEInfo->dwSectionAlign +
						pSectionHeader->VirtualAddress;
	}
	

	for (DWORD i = 0; i < dwNumOfSections ; i++ , pSectionHeader ++)
	{
		if (!strcmp((CHAR*)pSectionHeader->Name, ".tls"))
		{
			*dwTlsSectionStartRVA	= pSectionHeader->VirtualAddress;
			*dwSectionRealSize		= pSectionHeader->Misc.VirtualSize;
			return TRUE;
		}
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////////
//	设置对应类型的数据目录项参数
//	参数：
//	DWORD dwType			数据项类型
//	DWORD dwVirtualAddress	对应RVA
//	DWORD dwSize			对应真实大小
//////////////////////////////////////////////////////////////////////////

VOID	COperationPE::SetDir(DWORD dwType, DWORD dwVirtualAddress, DWORD dwSize)
{
	PIMAGE_DATA_DIRECTORY pRelocDir = &(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	PIMAGE_DATA_DIRECTORY pDir = NULL;
	switch (dwType)
	{
	case IMAGE_DIRECTORY_ENTRY_BASERELOC:
		pDir = &(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
		break;
	case IMAGE_DIRECTORY_ENTRY_TLS:
		pDir = &(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]);
		break;
	case IMAGE_DIRECTORY_ENTRY_IAT:
		pDir = &(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]);
		break;
	case  IMAGE_DIRECTORY_ENTRY_EXPORT:
		pDir = &(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
		break;
	default:
		break;
	}

	if (!pDir)		return;

	pDir->VirtualAddress = dwVirtualAddress;
	pDir->Size			 = dwSize;


}


//////////////////////////////////////////////////////////////////////////
//	将宿主程序的tls数据区覆盖到shell的数据区中
//	参数：
//	DWORD	dwStartAddr				宿主程序tls的模板数据起始地址
//	DWORD	dwEndAddr				宿主程序tls的模板数据末地址
//	DWORD	dwIndexValue			宿主程序tls
//////////////////////////////////////////////////////////////////////////

BOOL	COperationPE::ChangeModuleData(DWORD dwStartAddr, DWORD dwEndAddr, DWORD dwIndexValue)
{
	PIMAGE_TLS_DIRECTORY	pTls		=  (PIMAGE_TLS_DIRECTORY)(m_dwFileDataAddr +  RVAToOffset( m_stcPeInfo.stcPETlsDir.VirtualAddress));
	
	if (!pTls)		return FALSE;

	*(PDWORD)(RVAToOffset(pTls->AddressOfIndex - m_stcPeInfo.dwImageBase) + m_dwFileDataAddr) = dwIndexValue;

	pTls->StartAddressOfRawData = dwStartAddr;
	pTls->EndAddressOfRawData	= dwEndAddr;

	return TRUE;

}

//////////////////////////////////////////////////////////////////////////
//	获得目标程序的模板数据及其数据大小
//	返回值：	宿主程序的tls表
//////////////////////////////////////////////////////////////////////////

VOID	COperationPE::ReturnTlsModuleAddress(PDWORD dwStartAddr, PDWORD dwEndAddr, PDWORD dwIndexValue)
{
	PIMAGE_TLS_DIRECTORY	pTls	= (PIMAGE_TLS_DIRECTORY)(m_dwFileDataAddr + RVAToOffset(m_stcPeInfo.stcPETlsDir.VirtualAddress));

	*dwStartAddr	= pTls->StartAddressOfRawData;
	*dwEndAddr		= pTls->EndAddressOfRawData;
	*dwIndexValue	= *(PDWORD)(RVAToOffset(pTls->AddressOfIndex - m_stcPeInfo.dwImageBase) + m_dwFileDataAddr);
	
}


//////////////////////////////////////////////////////////////////////////
//	获取导出表的缓冲区和大小,将AddOfName的数组Copy出来
//	参数：
//	PDWORD		dwSize			[out]导出表大小
//	返回值：					导出表缓冲区
//////////////////////////////////////////////////////////////////////////

VOID	COperationPE::GetExportBuf( pPEInfo pPeInfo)
{
	DWORD dwSize					= pPeInfo->pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	PIMAGE_EXPORT_DIRECTORY	pExp	= (PIMAGE_EXPORT_DIRECTORY)(RVAToOffset(m_stcPeInfo.pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) + m_dwFileDataAddr);

	PDWORD	pName					= (PDWORD)(RVAToOffset(pExp->AddressOfNames) + m_dwFileDataAddr);

	DWORD	dwNumOfName				= pExp->NumberOfNames;

	pPeInfo->pExpAddrOfName		= new DWORD[dwNumOfName + 1];

	ZeroMemory(pPeInfo->pExpAddrOfName, sizeof(DWORD)*(dwNumOfName + 1));

	//复制AddOfName的内容
	while (dwNumOfName >0)
	{
		CopyMemory(pPeInfo->pExpAddrOfName, pName, dwNumOfName * sizeof(DWORD));
		dwNumOfName--;
	}


	pPeInfo->pExportBuf = new BYTE[dwSize];

	CopyMemory(pPeInfo->pExportBuf,
		(LPBYTE)(RVAToOffset(m_stcPeInfo.pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) + m_dwFileDataAddr),
		dwSize);

}


//////////////////////////////////////////////////////////////////////////
//	根据旧导出表的字段偏移重定位新表的各字段偏移
//	参数：
//	DWORD					dwNewExportRVA				新导出表的RVA
//	PIMAGE_EXPORT_DIRECTORY	pNewExp						新导出表所在地址(还未修复，其中字段仍是旧的RVA地址)
//////////////////////////////////////////////////////////////////////////

BOOL	COperationPE::RelocExportTable(DWORD dwNewExportRVA, PIMAGE_EXPORT_DIRECTORY	pNewExp)
{
	DWORD					dwOldExpRVA = m_stcPeInfo.pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	DWORD					dwNumOfName;

	if (!dwOldExpRVA || !dwNewExportRVA  || !pNewExp)	return FALSE;


	pNewExp->AddressOfFunctions		= dwNewExportRVA + pNewExp->AddressOfFunctions - dwOldExpRVA;

	pNewExp->AddressOfNameOrdinals	= dwNewExportRVA + pNewExp->AddressOfNameOrdinals - dwOldExpRVA;

	pNewExp->Name					= dwNewExportRVA + pNewExp->Name - dwOldExpRVA;

	dwNumOfName						= 0;

	PDWORD					pAddrOfName = (PDWORD)(pNewExp->AddressOfNames - dwOldExpRVA + (DWORD)pNewExp);
		
	for(dwNumOfName = 0; dwNumOfName <pNewExp->NumberOfNames; dwNumOfName++)
	{
		*pAddrOfName = m_stcPeInfo.pExpAddrOfName[dwNumOfName] + dwNewExportRVA - dwOldExpRVA;
	
		pAddrOfName++;

	}

	pNewExp->AddressOfNames = dwNewExportRVA + pNewExp->AddressOfNames - dwOldExpRVA;

	return	TRUE;
}


//////////////////////////////////////////////////////////////////////////
//	对数据进行压缩，压缩库是Aplib
//	参数：
//	LPBYTE	pData			待压缩数据的缓冲区
//	DWORD	dwSize			待压缩数据大小
//	PDWORD	dwPackedSize	[out]压缩后的数据大小
//	返回值：				压缩数据的缓冲区
//////////////////////////////////////////////////////////////////////////

LPBYTE	COperationPE::CompressDataOfAplib(LPBYTE pData, DWORD dwSize, PDWORD dwPackedSize)
{
	DWORD	dwPackedFileSize;
	DWORD	dwMemWorkPlace;
	DWORD	dwPackedRealSize;

	dwPackedFileSize = aP_max_packed_size(dwSize);

	dwMemWorkPlace = aP_workmem_size(dwSize);

	LPBYTE	pPackedFile = new BYTE[dwPackedFileSize];

	LPBYTE	pWorkMem = new BYTE[dwMemWorkPlace];

	ZeroMemory(pWorkMem, dwMemWorkPlace);

	ZeroMemory(pPackedFile, dwPackedFileSize);


	dwPackedRealSize = aPsafe_pack(pData, pPackedFile, dwSize, pWorkMem, NULL, NULL);

	*dwPackedSize = dwPackedRealSize;

	delete[] pWorkMem;

	if (dwPackedRealSize == APLIB_ERROR)
	{
		delete[] pPackedFile;
		return NULL;
	}


	return pPackedFile;
}

//////////////////////////////////////////////////////////////////////////
//	将所有区段进行压缩，并融合为一个区段，压缩后第一个区段为占位区段
//	将压缩过程中的区段关键信息保存在一个结构体中，其指针存放在宿主程序的PE结构体中
//	可以对tls表进行特殊处理
//	参数：
//	pPEInfo					pObjectPE	宿主程序的PE关键信息结构体
//////////////////////////////////////////////////////////////////////////

VOID	COperationPE::CompressSection(pPEInfo pObjectPE, PSelectionInfo pSelect)
{
	PIMAGE_SECTION_HEADER	pSecHeader		= IMAGE_FIRST_SECTION(m_pNtHeader);
	DWORD					dwCompressSecRva;
	DWORD					dwOccupiedSecEndRva;
	DWORD					dwNumOfSection	= m_pNtHeader->FileHeader.NumberOfSections;
	DWORD					dwLastSecVS		= pSecHeader[dwNumOfSection - 1].Misc.VirtualSize;
	DWORD					dwLastSecRva	= pSecHeader[dwNumOfSection - 1].VirtualAddress;
	DWORD					dwCompressedSize;
	
	// 1.1计算出占位区段的信息
	if (dwLastSecVS % pObjectPE->dwSectionAlign)
	{
		dwCompressSecRva = (dwLastSecVS / pObjectPE->dwSectionAlign + 1)*pObjectPE->dwSectionAlign + dwLastSecRva;
	}
	else
	{
		dwCompressSecRva = (dwLastSecVS / pObjectPE->dwSectionAlign)*pObjectPE->dwSectionAlign + dwLastSecRva;
	}
	
	dwOccupiedSecEndRva = dwCompressSecRva;

	// 1.2保存节表
	PIMAGE_SECTION_HEADER	pOriginalSecTable = new IMAGE_SECTION_HEADER[dwNumOfSection];

	CopyMemory(pOriginalSecTable, pSecHeader, dwNumOfSection * sizeof(IMAGE_SECTION_HEADER));
	
	pObjectPE->pOriginalSecTable = (LPBYTE)pOriginalSecTable;


	
	// 2.压缩区段
	PComPressInfo	pSecComPressInfo = new ComPressInfo[dwNumOfSection];
	pObjectPE->pCompressInfo = (LPBYTE)pSecComPressInfo;

	for (DWORD dwIndex = 0; dwIndex < dwNumOfSection; dwIndex++)
	{
		if (pSecHeader[dwIndex].SizeOfRawData  == 0)
		{
			ZeroMemory(&pSecComPressInfo[dwIndex], sizeof(ComPressInfo));
			continue;
		}

		if(pSelect->dwCompressionType == COMPRESS_APLIB)
		pSecComPressInfo[dwIndex].pData = CompressDataOfAplib((LPBYTE)(pSecHeader[dwIndex].PointerToRawData + m_dwFileDataAddr),
											pSecHeader[dwIndex].SizeOfRawData,
											&dwCompressedSize);

		if (pSelect->dwCompressionType == COMPRESS_JCALG1_FAST  || pSelect->dwCompressionType == COMPRESS_JCALG1_SMALL)
			pSecComPressInfo[dwIndex].pData = ComressDataOfJCALG1((LPBYTE)(pSecHeader[dwIndex].PointerToRawData + m_dwFileDataAddr),
				pSecHeader[dwIndex].SizeOfRawData,
				&dwCompressedSize);


		if (pSecComPressInfo[dwIndex].pData == NULL)
		{
			MessageBox(NULL, L"压缩失败，程序即将退出!", L"错误", NULL);
			exit(0);
		}

		pSecComPressInfo[dwIndex].CompressSize	= dwCompressedSize;

		pSecComPressInfo[dwIndex].OriginalRva	= pSecHeader[dwIndex].VirtualAddress;

		pSecComPressInfo[dwIndex].CompressRva	= dwCompressSecRva;

		//以文件粒度对齐是为了节省空间，可能后期会有问题，先保留

		if (dwCompressedSize % pObjectPE->dwFileAlign)
		{
			dwCompressSecRva += ((dwCompressedSize / pObjectPE->dwFileAlign + 1)*pObjectPE->dwFileAlign);
		}
		else
		{
			dwCompressSecRva += ((dwCompressedSize / pObjectPE->dwFileAlign)*pObjectPE->dwFileAlign);
		}
		
	}


	// 3.1 修改PE头，占位区段+压缩区段

	m_pNtHeader->FileHeader.NumberOfSections = 2;
	
	// PS:记住，还要修改镜像大小

	ZeroMemory(pSecHeader, dwNumOfSection * sizeof(IMAGE_SECTION_HEADER));

	//写入占位区段信息
	//bug,要让占位段的偏移为PE头的大小
	pSecHeader[0].PointerToRawData	= pObjectPE->dwSizeOfHeader;
	pSecHeader[0].SizeOfRawData		= 0;
	pSecHeader[0].VirtualAddress	= pObjectPE->dwSectionAlign;
	pSecHeader[0].Misc.VirtualSize	= dwOccupiedSecEndRva - pObjectPE->dwSectionAlign;
	pSecHeader[0].Characteristics	= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
	memcpy(pSecHeader[0].Name, ".pack0", strlen(".pack0"));
	
	//写入压缩区段信息
	//bug
	pSecHeader[1].PointerToRawData	= pObjectPE->dwSizeOfHeader;

	if ((dwCompressSecRva - dwOccupiedSecEndRva) % pObjectPE->dwSectionAlign)
	{
		pSecHeader[1].Misc.VirtualSize	= ((dwCompressSecRva - dwOccupiedSecEndRva) / pObjectPE->dwSectionAlign + 1)*pObjectPE->dwSectionAlign;
	}
	else
	{
		pSecHeader[1].Misc.VirtualSize	= ((dwCompressSecRva - dwOccupiedSecEndRva) / pObjectPE->dwSectionAlign)*pObjectPE->dwSectionAlign;
	}


	if ((dwCompressSecRva - dwOccupiedSecEndRva) % pObjectPE->dwFileAlign)
	{
		pSecHeader[1].SizeOfRawData = ((dwCompressSecRva - dwOccupiedSecEndRva) / pObjectPE->dwFileAlign + 1)*pObjectPE->dwFileAlign;
	}
	else
	{
		pSecHeader[1].SizeOfRawData = ((dwCompressSecRva - dwOccupiedSecEndRva) / pObjectPE->dwFileAlign)*pObjectPE->dwFileAlign;
	}



//	pSecHeader[1].SizeOfRawData			= pSecHeader[1].Misc.VirtualSize;
	pSecHeader[1].VirtualAddress		= dwOccupiedSecEndRva;
	pSecHeader[1].Characteristics		= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	memcpy(pSecHeader[1].Name, ".pack1", strlen(".pack1"));

	//将压缩信息写入
	for (DWORD dwIndex = 0; dwIndex < dwNumOfSection ; dwIndex++)
	{
		CopyMemory((PVOID)(m_dwFileDataAddr + RVAToOffset(pSecComPressInfo[dwIndex].CompressRva)),
			pSecComPressInfo[dwIndex].pData,
			pSecComPressInfo[dwIndex].CompressSize);
	}



	m_pNtHeader->OptionalHeader.SizeOfImage = pObjectPE->dwSectionAlign +
		AlignSize(pSecHeader[0].Misc.VirtualSize, pObjectPE->dwSectionAlign) +
		AlignSize(pSecHeader[1].Misc.VirtualSize, pObjectPE->dwSectionAlign);


}


//////////////////////////////////////////////////////////////////////////
//	使长度以指定的粒度对齐
//	参数：
//	DWORD		dwSize		数据长度
//	DWORD		dwAlign		对齐粒度

DWORD	 COperationPE::AlignSize(DWORD dwSize, DWORD dwAlign)
{

	if (dwSize % dwAlign)
	{
		return (dwSize / dwAlign + 1)*dwAlign;
	}
	else
	{
		return (dwSize / dwAlign)*dwAlign;
	}

}


//////////////////////////////////////////////////////////////////////////
//	以特定的结构体保存导入表,简称转储
//	参数：
//	DWORD			dwNewAddr		申请存放解析之后导入表的缓冲区
//	返回值：						该表的大小
//////////////////////////////////////////////////////////////////////////

DWORD	COperationPE::MoveImportTable(DWORD dwNewAddr)
{
	PIMAGE_IMPORT_DESCRIPTOR	pImport = (PIMAGE_IMPORT_DESCRIPTOR)(RVAToOffset(m_stcPeInfo.stcPEImportDir.VirtualAddress)
											+ m_dwFileDataAddr);
	PIMAGE_THUNK_DATA			pThunk;
	PIMAGE_IMPORT_BY_NAME		pImportByName;

	DWORD						dwCounter;
	LPBYTE						pTemp = (LPBYTE)dwNewAddr;
	PDWORD						pFunNum;
	CHAR*						szDllName;
	

	if (!dwNewAddr)	return NULL;


	while (pImport->Name)
	{
		dwCounter = 0;

		*(PDWORD)pTemp = pImport->FirstThunk;

		pTemp += sizeof(DWORD);

		szDllName = (CHAR*)(m_dwFileDataAddr + RVAToOffset(pImport->Name));

		*pTemp =  (BYTE)strlen(szDllName);

		pTemp++;

		CopyMemory(pTemp, szDllName, strlen(szDllName)+1 );

		pTemp += strlen(szDllName) + 1;

		pFunNum = (PDWORD)pTemp;

		pTemp += sizeof(DWORD);

		//做特殊处理
		if (pImport->OriginalFirstThunk == 0)
		{
			pThunk = (PIMAGE_THUNK_DATA)(m_dwFileDataAddr + RVAToOffset(pImport->FirstThunk));
		}
		else
		{
			pThunk = (PIMAGE_THUNK_DATA)(m_dwFileDataAddr + RVAToOffset(pImport->OriginalFirstThunk));
		}


		while (pThunk->u1.AddressOfData)
		{

			if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
			{//序号
				*pTemp = 0x0;
				pTemp++;
				*(PDWORD)pTemp = pThunk->u1.Ordinal & 0x7FFFFFFF;
				pTemp += sizeof(DWORD);
			}
			else
			{//字符串
				pImportByName = (PIMAGE_IMPORT_BY_NAME)(RVAToOffset( pThunk->u1.AddressOfData) + m_dwFileDataAddr);

				*pTemp = (BYTE)strlen(pImportByName->Name);

				pTemp++;

				CopyMemory(pTemp, pImportByName->Name, strlen(pImportByName->Name)+1);
		
				pTemp += strlen(pImportByName->Name) + 1;

			}

			dwCounter++;
			pThunk++;

		}


		*pFunNum = dwCounter;
		pImport++;
	}

	//结束标志
	*(PDWORD)pTemp = 0x0;		
	pTemp += sizeof(DWORD);

	return	(DWORD)pTemp - dwNewAddr;

}



//////////////////////////////////////////////////////////////////////////
//	清空导入表
//////////////////////////////////////////////////////////////////////////

BOOL	COperationPE::CleanImportTable()
{
	PIMAGE_IMPORT_DESCRIPTOR	pImport = (PIMAGE_IMPORT_DESCRIPTOR)(RVAToOffset(m_stcPeInfo.stcPEImportDir.VirtualAddress)
		+ m_dwFileDataAddr);
	PIMAGE_THUNK_DATA			pThunk;
	PIMAGE_IMPORT_BY_NAME		pImportByName;
	CHAR*						szDllName;
	DWORD						dwOffset = 0;

	if (!m_stcPeInfo.stcPEImportDir.VirtualAddress)	return FALSE;
	

	while (pImport->Name)
	{
		szDllName = (CHAR*)(RVAToOffset(pImport->Name) + m_dwFileDataAddr);

		ZeroMemory(szDllName, strlen(szDllName));

		if(pImport->OriginalFirstThunk)
		{
			pThunk = (PIMAGE_THUNK_DATA)(RVAToOffset(pImport->OriginalFirstThunk) + m_dwFileDataAddr);
			while (pThunk->u1.AddressOfData)
			{
				if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
				{//序号
					ZeroMemory(pThunk, sizeof(DWORD));
				}
				else
				{//字符串
					pImportByName = (PIMAGE_IMPORT_BY_NAME)(RVAToOffset(pThunk->u1.AddressOfData) + m_dwFileDataAddr);
					ZeroMemory(pImportByName->Name, strlen(pImportByName->Name));
					pImportByName->Hint = 0x0;
					ZeroMemory(pThunk, sizeof(DWORD));
				}
				pThunk++;
			}
		}//if


			pThunk = (PIMAGE_THUNK_DATA)(RVAToOffset(pImport->FirstThunk) + m_dwFileDataAddr);
			while (pThunk->u1.AddressOfData)
			{
				if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
				{//序号
					ZeroMemory(pThunk, sizeof(DWORD));
				}
				else
				{//字符串
					dwOffset = RVAToOffset(pThunk->u1.AddressOfData);
					if(dwOffset == 0)	break;
					pImportByName = (PIMAGE_IMPORT_BY_NAME)(RVAToOffset(pThunk->u1.AddressOfData) + m_dwFileDataAddr);
					ZeroMemory(pImportByName, strlen(pImportByName->Name) +sizeof(WORD));	
					ZeroMemory(pThunk, sizeof(DWORD));
				}

				pThunk++;
			}
		
			ZeroMemory(pImport, sizeof(IMAGE_IMPORT_DESCRIPTOR));
			pImport++;
	}


	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//	转储重定位表，按照《加密与解密》第三版中的结构组织
//	参数：
//	DWORD		dwNewAddr			保存转储数据的缓冲区地址
//	返回值：						缓冲区大小
//////////////////////////////////////////////////////////////////////////

DWORD	COperationPE::MoveRelocTable(DWORD dwNewAddr)
{
	typedef struct _TYPEOFFSET
	{
		WORD offset : 12;			//偏移值
		WORD Type : 4;			//重定位属性(方式)
	}TYPEOFFSET, *PTYPEOFFSET;


	PIMAGE_BASE_RELOCATION	pReloc = (PIMAGE_BASE_RELOCATION)(m_dwFileDataAddr + RVAToOffset(m_stcPeInfo.stcPERelocDir.VirtualAddress));
	DWORD					dwRelocOfItemNum;
	PTYPEOFFSET				pOffset;
	DWORD					dwNewItemOffset = 0;
	DWORD					dwTemp			= 0;
	LPBYTE					pData			= (LPBYTE)dwNewAddr;


	while (pReloc->VirtualAddress)
	{

		dwRelocOfItemNum	= (pReloc->SizeOfBlock - 8) / 2;
		pOffset				= (PTYPEOFFSET)((DWORD)pReloc + sizeof(IMAGE_BASE_RELOCATION));
		
		for (DWORD dwIndex = 0; dwIndex < dwRelocOfItemNum; dwIndex++, pOffset++)
		{
			if (pOffset->Type == IMAGE_REL_BASED_HIGHLOW)
			{
				dwNewItemOffset = pOffset->offset + pReloc->VirtualAddress - dwTemp;

				if (dwNewItemOffset > 0xfff)
				{//如果是第一个重定位项的话
					*pData = IMAGE_REL_BASED_HIGHLOW;
					pData++;
					*(PDWORD)pData = dwNewItemOffset;
					pData += sizeof(DWORD);
					
				}
				else
				{

					*(PWORD)pData = (WORD)dwNewItemOffset;
					pData += sizeof(WORD);
				}

				dwTemp += dwNewItemOffset;
			}//if


		}//for

		*(PWORD)pData = 0x0; //作为一页的结束符
		pData += sizeof(WORD);
		dwTemp = 0;
		dwNewItemOffset = 0;

		pReloc = (PIMAGE_BASE_RELOCATION)(pReloc->SizeOfBlock + (DWORD)pReloc);
	}//while

	*(PWORD)pData = 0x0;
	pData += sizeof(WORD);

	return (DWORD)pData - dwNewAddr;

}

//////////////////////////////////////////////////////////////////////////
//	清空重定位表
//////////////////////////////////////////////////////////////////////////

BOOL	COperationPE::CleanRelocTable()
{
	typedef struct _TYPEOFFSET
	{
		WORD offset : 12;			//偏移值
		WORD Type : 4;			//重定位属性(方式)
	}TYPEOFFSET, *PTYPEOFFSET;


	PIMAGE_BASE_RELOCATION	pReloc = (PIMAGE_BASE_RELOCATION)(m_dwFileDataAddr + RVAToOffset(m_stcPeInfo.stcPERelocDir.VirtualAddress));
	DWORD					dwRelocOfItemNum;
	DWORD					dwSizeOfBlock;
	PTYPEOFFSET				pOffset;
	

	if (!m_stcPeInfo.stcPERelocDir.VirtualAddress)	return FALSE;
	

	while (pReloc->VirtualAddress)
	{
		dwRelocOfItemNum = (pReloc->SizeOfBlock - 8) / 2;
		pOffset = (PTYPEOFFSET)((DWORD)pReloc + sizeof(IMAGE_BASE_RELOCATION));
		dwSizeOfBlock = pReloc->SizeOfBlock;

		for (DWORD dwIndex = 0; dwIndex < dwRelocOfItemNum; dwIndex++, pOffset++)
		{
			pOffset->offset = 0x0;
			pOffset->Type	= 0x0;
		}

		memset(pReloc, 0, sizeof(IMAGE_BASE_RELOCATION));

		pReloc = (PIMAGE_BASE_RELOCATION)(dwSizeOfBlock + (DWORD)pReloc);
	}

	m_stcPeInfo.pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0x0;
	m_stcPeInfo.pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0x0;


	return TRUE;
}


void * _stdcall AllocFunc(DWORD nMemSize)
{
	return (VOID *)GlobalAlloc(GMEM_FIXED, nMemSize);
}

bool _stdcall DeallocFunc(void *pBuffer)
{
	GlobalFree((HGLOBAL)pBuffer);
	return true;
}

bool _stdcall CallbackFunc(DWORD pSourcePos, DWORD pDestinationPos)
{
	return true;
}


//////////////////////////////////////////////////////////////////////////
//	对数据进行压缩，压缩库是JCALG1
//	参数：
//	LPBYTE					pData			原始数据的缓冲区
//	DWORD					dwSize			原始数据缓冲区的大小
//	PDWORD					dwPackedSize	[out]压缩数据的大小
//	返回值：								压缩数据的缓冲区
//////////////////////////////////////////////////////////////////////////

LPBYTE	COperationPE::ComressDataOfJCALG1(LPBYTE pData, DWORD dwSize, PDWORD dwPackedSize)
{
	DWORD	dwCompressedSize;
	DWORD	dwWindowSize = 4 * 1024;
	DWORD	dwMemSize = JCALG1_GetNeededBufferSize(dwSize);
	LPBYTE pBuffer = new BYTE[dwMemSize + 1];

	ZeroMemory(pBuffer, dwMemSize);
	dwCompressedSize =
		JCALG1_Compress((void *)pData, dwSize, (void *)pBuffer, dwWindowSize, &AllocFunc, &DeallocFunc, &CallbackFunc, 0);

	if (!dwCompressedSize)
	{	
		delete[] pBuffer;
		return NULL;
	}

	*dwPackedSize = dwCompressedSize;
	return pBuffer;
}



//////////////////////////////////////////////////////////////////////////
//	生成CRC32表格
//////////////////////////////////////////////////////////////////////////

VOID	COperationPE::MakeCRC32Table()
{
	uint32_t c;
	int i = 0;
	int bit = 0;

	for (i = 0; i < 256; i++)
	{
		c = (uint32_t)i;

		for (bit = 0; bit < 8; bit++)
		{
			if (c & 1)
			{
				c = (c >> 1) ^ (0xEDB88320);
			}
			else
			{
				c = c >> 1;
			}

		}
		crc32_table[i] = c;
	}



}


//////////////////////////////////////////////////////////////////////////
//	计算给定区域的CRC32值
//	参数：
//	UCHAR *		string	- 数据块指针
//	uint32_t	size	- 数据的大小
//	返回值：计算好的CRC32值
//////////////////////////////////////////////////////////////////////////


DWORD	COperationPE::CalcuCRC(UCHAR *string, uint32_t size)
{
	//计算因子为-1
	uint32_t crc = 0xFFFFFFFF;


	while (size--)
		crc = (crc >> 8) ^ (crc32_table[(crc ^ *string++) & 0xff]);

	return crc;

}



//////////////////////////////////////////////////////////////////////////
//	计算CRC值，并保存到PE标识前4个byte中
//	参数：
//	DWORD				dwFileSize	- 文件大小
//	注：需要减去DOS头及DOS Stub的大小，只计算PE头之后的数据
//	
//////////////////////////////////////////////////////////////////////////

VOID	COperationPE::CalAndSaveCRC(DWORD dwFileSize)
{
	DWORD	dwCrc32;	//计算的值

	//1. 生成CRC32表格
	if(m_bCRC32Table == FALSE)
		MakeCRC32Table();

	//2. 计算PE头之后的数据
	dwCrc32 = CalcuCRC((UCHAR*)(m_pDosHeader->e_lfanew + m_dwFileDataAddr), dwFileSize - m_pDosHeader->e_lfanew);

	//3. 将该CRC32值写进PE头标识前4个字节
	*(PDWORD)((DWORD)m_pNtHeader - 4) = dwCrc32;

}


//////////////////////////////////////////////////////////////////////////
//	为内存中的代码段生成CRC校验值,并将返回值保存在成员变量中
//	生成CRC32表格
//	参数：
//	LPBYTE		pCodeBase		- 代码段的数据区
//	DWORD		dwSize			- 以内存粒度对齐后的代码段大小
//////////////////////////////////////////////////////////////////////////

VOID	COperationPE::CalMemCRC(LPBYTE pCodeBase, DWORD dwSize, pPEInfo pObjectPE)
{

	//1. 生成CRC32表格
	if (m_bCRC32Table == FALSE)
		MakeCRC32Table();

	//2. 计算代码段CRC32值
	pObjectPE->dwCodeMemCRC32 = CalcuCRC((UCHAR*)pCodeBase, dwSize);

}
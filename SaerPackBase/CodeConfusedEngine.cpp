#include "stdafx.h"
#include "CodeConfusedEngine.h"


//////////////////////////////////////////////////////////////////////////
//	对相关数据区进行反汇编,将跳转和call指令写入链表中
//	参数：
//	COperationPE* pObjectPE		- 目标程序的PE操作类指针
//	PEInfo stcPeInfo			- 目标程序的PE关键信息结构体
//	CONST LPBYTE  pStart		- 代码段指针
//	DWORD dwSize				- 代码段长度
//////////////////////////////////////////////////////////////////////////

pCode_Flow_Node DrawCodeFlow(COperationPE* pObjectPE, pPEInfo pPeInfo, CONST LPBYTE pStart, DWORD dwSize)
{
	pCode_Flow_Node pCodeFlow = new Code_Flow_Node;
	pCode_Flow_Node pCodeFlowHeader = NULL, *pCodeFlowNode = &pCodeFlowHeader;
	LPBYTE			pCurInpPtr;
	LPBYTE			pCurr = pStart;
	LPBYTE			pFileAddr = (LPBYTE)pObjectPE->GetFileAddr();
	DWORD			dwRva;
	DWORD			dwRaw;
	DWORD			dwOffset;
	pImport_Node	pImpHeader;
	DWORD			dwFunIndex;
	PDWORD			pdValInMem;
	//解析导入表
	pImpHeader = DrawIATNode(pObjectPE, pPeInfo);

	if (pImpHeader == NULL)
		return NULL;
	

	// 初始化反汇编引擎
	ud_t ud_obj;
	ud_init(&ud_obj);
	ud_set_input_buffer(&ud_obj, pStart, dwSize);
	ud_set_mode(&ud_obj, 32);
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);

	while (ud_disassemble(&ud_obj) != 0)
	{
		if (ud_obj.mnemonic == UD_Iinvalid)
			continue;
		
		// 判断是否是跳转地址
		switch (ud_obj.mnemonic)
		{
		case UD_Ijo:
		case UD_Ijno:
		case UD_Ijb:
		case UD_Ijae:
		case UD_Ijz:
		case UD_Ijnz:
		case UD_Ijbe:
		case UD_Ija:
		case UD_Ijs:
		case UD_Ijns:
		case UD_Ijp:
		case UD_Ijnp:
		case UD_Ijl:
		case UD_Ijge:
		case UD_Ijle:
		case UD_Ijg:
		case UD_Ijcxz:
		case UD_Ijecxz:
		case UD_Ijrcxz:
		{
			*pCodeFlowNode = new Code_Flow_Node;
			ZeroMemory(*pCodeFlowNode, sizeof(Code_Flow_Node));

			(*pCodeFlowNode)->bFar = FALSE;

			dwRva = pObjectPE->OffsetToRVA((DWORD)(pCurr - pFileAddr));
			(*pCodeFlowNode)->dwMemoryAddress = pPeInfo->dwImageBase + dwRva;
			(*pCodeFlowNode)->pFileAddress = pCurr;
			(*pCodeFlowNode)->dwType = JmpIns_Type_Jcc;
			(*pCodeFlowNode)->dwInsLen = ud_obj.inp_ctr;
			(*pCodeFlowNode)->pNext = NULL;
			(*pCodeFlowNode)->bConfused = FALSE;

			pCurInpPtr = (LPBYTE)ud_insn_ptr(&ud_obj);

			if (pCurInpPtr[0] == 0x0F)
			{//32bit
				dwOffset = ud_obj.operand[0].lval.udword;
				(*pCodeFlowNode)->dwOffset = dwOffset;
			
				if (dwOffset >= 0x80000000)
				{//向上跳
					(*pCodeFlowNode)->bGoDown = FALSE;
					dwOffset = ~dwOffset;
					dwOffset++;
					(*pCodeFlowNode)->dwGotoMemoryAddress = (*pCodeFlowNode)->dwMemoryAddress + ud_obj.inp_ctr \
						- dwOffset;

					dwRaw = pObjectPE->RVAToOffset((*pCodeFlowNode)->dwGotoMemoryAddress - pPeInfo->dwImageBase);
					(*pCodeFlowNode)->pGotoFileAddress = dwRaw + pFileAddr;

				}
				else
				{//向下跳
					(*pCodeFlowNode)->bGoDown = TRUE;
					(*pCodeFlowNode)->dwGotoMemoryAddress = (*pCodeFlowNode)->dwMemoryAddress + ud_obj.inp_ctr\
						+ dwOffset;

					dwRaw = pObjectPE->RVAToOffset((*pCodeFlowNode)->dwGotoMemoryAddress - pPeInfo->dwImageBase);
					(*pCodeFlowNode)->pGotoFileAddress = dwRaw + pFileAddr;
				}//if-else

				pCodeFlowNode = &((*pCodeFlowNode)->pNext);
			}
			else
			{//8bit
				//忽略
				delete *pCodeFlowNode;
				*pCodeFlowNode = NULL;
			}

		}
		break;
		case UD_Ijmp:
		{
			*pCodeFlowNode = new Code_Flow_Node;
			ZeroMemory(*pCodeFlowNode, sizeof(Code_Flow_Node));


			(*pCodeFlowNode)->bFar = FALSE;

			dwRva = pObjectPE->OffsetToRVA((DWORD)(pCurr - pFileAddr));
			(*pCodeFlowNode)->dwMemoryAddress = pPeInfo->dwImageBase + dwRva;
			(*pCodeFlowNode)->pFileAddress = pCurr;
			(*pCodeFlowNode)->dwType = JmpIns_Type_Jmp;
			(*pCodeFlowNode)->dwInsLen = ud_obj.inp_ctr;
			(*pCodeFlowNode)->pNext = NULL;
			(*pCodeFlowNode)->bConfused = FALSE;

			pCurInpPtr = (LPBYTE)ud_insn_ptr(&ud_obj);

			if (pCurInpPtr[0] == 0xE9)
			{//32bit

				(*pCodeFlowNode)->dwOffset = ud_obj.operand[0].lval.udword;
				dwOffset = (*pCodeFlowNode)->dwOffset;

				if (dwOffset >= 0x80000000)
				{//向上跳
					(*pCodeFlowNode)->bGoDown = FALSE;
					dwOffset = ~dwOffset;
					dwOffset++;
					(*pCodeFlowNode)->dwGotoMemoryAddress = (*pCodeFlowNode)->dwMemoryAddress + ud_obj.inp_ctr \
						- dwOffset;

					dwRaw = pObjectPE->RVAToOffset((*pCodeFlowNode)->dwGotoMemoryAddress - pPeInfo->dwImageBase);
					(*pCodeFlowNode)->pGotoFileAddress = dwRaw + pFileAddr;

				}
				else
				{//向下跳
	
					(*pCodeFlowNode)->bGoDown = TRUE;
					(*pCodeFlowNode)->dwGotoMemoryAddress = (*pCodeFlowNode)->dwMemoryAddress + ud_obj.inp_ctr \
						+ dwOffset;

					dwRaw = pObjectPE->RVAToOffset((*pCodeFlowNode)->dwGotoMemoryAddress - pPeInfo->dwImageBase);
					(*pCodeFlowNode)->pGotoFileAddress = dwRaw + pFileAddr;
				}//if-else

				pCodeFlowNode = &((*pCodeFlowNode)->pNext);

			}
			else
			{//8bit
				//忽略
				delete *pCodeFlowNode;
				*pCodeFlowNode = NULL;
			}
		}
		break;
		case UD_Icall:
		{
			*pCodeFlowNode = new Code_Flow_Node;
			ZeroMemory(*pCodeFlowNode, sizeof(Code_Flow_Node));

			(*pCodeFlowNode)->bFar = FALSE;

			dwRva = pObjectPE->OffsetToRVA((DWORD)(pCurr - pFileAddr));
			(*pCodeFlowNode)->dwMemoryAddress = pPeInfo->dwImageBase + dwRva;
			(*pCodeFlowNode)->pFileAddress = pCurr;
			(*pCodeFlowNode)->dwType = JmpIns_Type_Call;
			(*pCodeFlowNode)->dwInsLen = ud_obj.inp_ctr;
			(*pCodeFlowNode)->pNext = NULL;
			(*pCodeFlowNode)->bConfused = FALSE;

			dwOffset = ud_obj.operand[0].lval.udword;
			(*pCodeFlowNode)->dwOffset = dwOffset;

			pCurInpPtr = (LPBYTE)ud_insn_ptr(&ud_obj);

			if (pCurInpPtr[0] == 0xE8)
			{//E8+偏移

				if (dwOffset >= 0x80000000)
				{//向上跳
					(*pCodeFlowNode)->bGoDown = FALSE;
					dwOffset = ~dwOffset;
					dwOffset++;
					(*pCodeFlowNode)->dwGotoMemoryAddress = (*pCodeFlowNode)->dwMemoryAddress + ud_obj.inp_ctr \
						- dwOffset;

					dwRaw = pObjectPE->RVAToOffset((*pCodeFlowNode)->dwGotoMemoryAddress - pPeInfo->dwImageBase);
					(*pCodeFlowNode)->pGotoFileAddress = dwRaw + pFileAddr;

				}
				else
				{//向下跳		
					(*pCodeFlowNode)->bGoDown = TRUE;
					(*pCodeFlowNode)->dwGotoMemoryAddress = (*pCodeFlowNode)->dwMemoryAddress + ud_obj.inp_ctr \
						+ dwOffset;

					dwRaw = pObjectPE->RVAToOffset((*pCodeFlowNode)->dwGotoMemoryAddress - pPeInfo->dwImageBase);
					(*pCodeFlowNode)->pGotoFileAddress = dwRaw + pFileAddr;
				}//if-else

				
				(*pCodeFlowNode)->pImpNode =  AnalyseDisp(pImpHeader, 
					(*pCodeFlowNode)->pGotoFileAddress,
					&dwFunIndex);
				(*pCodeFlowNode)->dwFunIndex = dwFunIndex;
		
				pCodeFlowNode = &((*pCodeFlowNode)->pNext);
			}
			else
			{//FF15+绝对地址
				//忽略，绝对地址无法做成花指令，否则需要重定位，BUG，留作以后改进
				delete *pCodeFlowNode;
				*pCodeFlowNode = NULL;	
			}//if-else

		}
		break;
		}//switch

		pCurr += ud_obj.inp_ctr;
	}//while

	return pCodeFlowHeader;
}


//////////////////////////////////////////////////////////////////////////
//	读取配置文件，获取花指令模块文件名的前缀，获取模板数量\
//	计算出模板长度平均值
//	参数：
//	LPWSTR ConfigPath		- 配置文件路径
//	LPWSTR ModPath			- [out]模板文件的前缀，包含绝对路径
//	PDWORD pdModNum			- [out]模板文件的数量
//	PDWORD* pdArrayMod		- [out]按顺序保存每个模板的大小，方便后续使用
//	返回值：
//	DWORD - 模板长度平均值	 ，若返回-1，则代表出错
//////////////////////////////////////////////////////////////////////////


DWORD	CalcAverageVal(LPWSTR ConfigPath, LPWSTR ModPath, PDWORD pdModNum, PDWORD* pdArrayMod)
{
	WCHAR	szModPath[MAX_PATH];
	WCHAR	szModPrefix_w[MAX_PATH];
	CHAR	szModPrefix[MAX_PATH];
	DWORD	dwPrefixLen;		
	DWORD	dwFileSize;
	DWORD	dwNumOfByteRead;
	DWORD	dwNumOfMod;		//花指令模板数量
	DWORD	dwAverage = 0;		//平均值
	PDWORD	ArrayMod;	//保存模板大小的数组
	LPBYTE	pFileBuf;
	HANDLE hFile = CreateFile(ConfigPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == NULL)
		return	-1;

	dwFileSize = GetFileSize(hFile, NULL);

	pFileBuf = new BYTE[dwFileSize];

	ZeroMemory(pFileBuf, dwFileSize);

	ZeroMemory(szModPrefix_w, MAX_PATH* sizeof(WCHAR));

	ZeroMemory(szModPrefix, MAX_PATH);

	ReadFile(hFile, pFileBuf, dwFileSize, &dwNumOfByteRead, NULL);

	strcpy_s(szModPrefix, (PCHAR)pFileBuf);

	dwPrefixLen = strlen((PCHAR)pFileBuf);

	MultiByteToWideChar(CP_ACP, NULL, szModPrefix,
		dwPrefixLen,
		szModPrefix_w,
		dwPrefixLen);


	//读取模板数量
	pFileBuf += (dwPrefixLen + 1);

	dwNumOfMod = *((PDWORD)(pFileBuf));

	*pdModNum = dwNumOfMod;

	ArrayMod = new DWORD[dwNumOfMod];

	ZeroMemory(ArrayMod, sizeof(DWORD)*dwNumOfMod);


	//读取每一个模板文件的长度

	for (DWORD dwIndex = 0; dwIndex < dwNumOfMod; dwIndex++)
	{
		pFileBuf += sizeof(DWORD);

		dwAverage += *((PDWORD)pFileBuf);

		ArrayMod[dwIndex] = *((PDWORD)pFileBuf);

	}
	
	dwAverage = dwAverage / dwNumOfMod;

	if (dwAverage % 10)
	{
		dwAverage = (dwAverage / 10 + 1) * 10;
	}



	HMODULE hModule = GetModuleHandle(L"SaerPackBase.dll");

	ZeroMemory(szModPath, sizeof(WCHAR)*MAX_PATH);

	GetModuleFileName(hModule, szModPath, MAX_PATH);

	//获取文件路径前缀
	PathRemoveFileSpec(szModPath);

	//判断是否为根目录
	BOOL bRootDir = PathIsRoot(szModPath);

	if (bRootDir)
	{//若是根目录，不用加反斜杠

		wsprintf(ModPath, L"%s\\JunkCodeMod\\%s", szModPath, szModPrefix_w);
	}
	else
	{
		
		wsprintf(ModPath, L"%s\\JunkCodeMod\\%s", szModPath, szModPrefix_w);
	}

	CloseHandle(hFile);

	*pdArrayMod = ArrayMod;

	return dwAverage;

}

//////////////////////////////////////////////////////////////////////////
//	获取配置文件的绝对路径
//	参数：
//	LPWSTR ConfigPath		- [in&out]文件路径
//	DWORD dwSize			- 缓冲区长度
//	返回值：
//	TRUE - 获取成功,否则返回FALSE
//////////////////////////////////////////////////////////////////////////

BOOL	GetConfigPath(LPWSTR ConfigPath, DWORD dwSize)
{
	HMODULE hModule = GetModuleHandle(L"SaerPackBase.dll");
	
	if (ConfigPath == NULL || hModule == NULL)
		return FALSE;

	ZeroMemory(ConfigPath, sizeof(WCHAR)*dwSize);

	if (GetModuleFileName(hModule, ConfigPath, dwSize) == NULL)
		return FALSE;

	//获取文件路径前缀
	if (PathRemoveFileSpec(ConfigPath) == NULL)
		return FALSE;

	//判断是否为根目录
	BOOL bRootDir = PathIsRoot(ConfigPath);

	if (bRootDir)
	{//若是根目录，不用加反斜杠
		wcscat_s(ConfigPath,dwSize, L"JunkCodeMod\\ModInfo.ini");	
	}
	else
	{
		wcscat_s(ConfigPath, dwSize, L"\\JunkCodeMod\\ModInfo.ini");
	}


	return TRUE;

}

//////////////////////////////////////////////////////////////////////////
//	获取链表节点数
//	参数：
//	pCode_Flow_Node pHeader		- 头结点
//	返回值：
//	节点的数量,用来估算花指令区段的大小，指令块平均长度*节点数
//////////////////////////////////////////////////////////////////////////

DWORD	GetNumOfNode(pCode_Flow_Node pHeader)
{
	DWORD dwNum = 0;

	if (pHeader == NULL)
		return dwNum;

	do 
	{
		dwNum++;
		pHeader = pHeader->pNext;
	} while (pHeader);

	return dwNum;

}

//////////////////////////////////////////////////////////////////////////
//	对链表中存储的跳转节点进行乱序操作
//	参数：
//	pCode_Flow_Node pHeader		- 链表的头结点
//	COperationPE* pObjectPE		- 目标程序的PE操作类
//	LPBYTE pNewSection			- 新区段的数据区指针
//	PIMAGE_SECTION_HEADER	pSecHeader	 - 新区段的头结构
//	DWORD	dwNumOfMod			- 模板的数量
//	LPWSTR	szModPrefix			- 模块路径的前缀
//	PDWORD	pdArrayMod			- 模板大小的数组
//	返回值：
//	TRUE - 成功 ,or else
//	注：对每个节点进行1/3的随机概率抽取
//////////////////////////////////////////////////////////////////////////

BOOL	ConfuseCode(pCode_Flow_Node pHeader,
	COperationPE* pObjectPE, 
	pPEInfo pPeInfo,
	LPBYTE pNewSection, 
	PIMAGE_SECTION_HEADER	pSecHeader,
	DWORD	dwNumOfMod,
	LPWSTR	szModPrefix,
	PDWORD	pdArrayMod,
	pSample_Array	pSampleArray,
	DWORD	dwTotalCtr)
{
	DWORD			dwRemainSize;
	DWORD			dwPeFileAddr;
	DWORD			dwCurSize;
	LPBYTE			lpFileBuf;
	LPBYTE			lpCurBuf;
	DWORD			dwOffset;
	pCode_Flow_Node	pCurNode;
	WCHAR			szTest[MAX_PATH];
	BOOL			bPassByRand = TRUE;		//随机函数 1/3的概率
	if (pObjectPE == NULL || pPeInfo == NULL || pNewSection == NULL || pdArrayMod == NULL  \
		|| szModPrefix == NULL)
		return FALSE;

	pCurNode	 = pHeader;
	dwPeFileAddr = pObjectPE->GetFileAddr();
	dwRemainSize = pSecHeader->SizeOfRawData;
	lpCurBuf	 = pNewSection;

	while (dwRemainSize >= 5 && pCurNode != NULL)
	{

		bPassByRand = RandomProbability(pSampleArray, dwTotalCtr, pCurNode->pImpNode, pCurNode->dwFunIndex);

		if (bPassByRand)
		{//随机抽中
			lpFileBuf = RandomMod(szModPrefix, dwNumOfMod, &dwRemainSize, pdArrayMod, &dwCurSize);

			if (lpFileBuf)
			{//空间足够

				//复制指令
				CopyMemory(lpCurBuf, lpFileBuf, dwCurSize);
				//lpCurBuf += dwCurSize;

				//计算花指令的内存地址和文件地址
				pCurNode->dwFinalFileAddress = (DWORD)lpCurBuf;
				pCurNode->dwFinalMemoryAddress = pObjectPE->OffsetToRVA((DWORD)lpCurBuf - dwPeFileAddr) \
					+ pPeInfo->dwImageBase;

	
				if (pObjectPE->OffsetToRVA((DWORD)lpCurBuf - dwPeFileAddr) == 0)
				{//BUG，暂时找不出,会因为lpCurBuf 比较大，导致OffsetToRVA越界返回0
					return FALSE;
				}


				//计算偏移
				//跳转到花指令
				dwOffset = pObjectPE->OffsetToRVA((DWORD)lpCurBuf - dwPeFileAddr) - \
					(pCurNode->dwMemoryAddress - pPeInfo->dwImageBase);

				if (pObjectPE->OffsetToRVA((DWORD)lpCurBuf - dwPeFileAddr) == 0)
				{//BUG，暂时找不出,会因为lpCurBuf 比较大，导致OffsetToRVA越界返回0
					return FALSE;
				}


				dwOffset -= pCurNode->dwInsLen;
				*((PDWORD)(pCurNode->pFileAddress + 1)) = dwOffset;

				//花指令跳转到目的地址
				lpCurBuf += dwCurSize;
				dwOffset = (pCurNode->dwGotoMemoryAddress - pPeInfo->dwImageBase) \
					- pObjectPE->OffsetToRVA((DWORD)lpCurBuf - dwPeFileAddr);

				dwOffset -= pCurNode->dwInsLen;
				*((PDWORD)(lpCurBuf + 1)) = dwOffset;
				*lpCurBuf = 0xE9;

				//处理完跳转地址,移动指针
				lpCurBuf += 0x5;
				pCurNode->bConfused = TRUE;
				delete lpFileBuf;

				dwCurSize += 0x5;

			}
			else
			{//空间不足,但足以存放一条跳转指令
				//计算偏移

				//计算花指令的内存地址和文件地址
				pCurNode->dwFinalFileAddress = (DWORD)lpCurBuf;
				pCurNode->dwFinalMemoryAddress = pObjectPE->OffsetToRVA((DWORD)lpCurBuf - dwPeFileAddr) \
					+ pPeInfo->dwImageBase;

				if (pCurNode->dwFinalMemoryAddress == 0x400000)
				{
					__asm int 3
				}


				//跳转到花指令,只有一条跳转指令
				dwOffset = pObjectPE->OffsetToRVA((DWORD)lpCurBuf - dwPeFileAddr) - \
					(pCurNode->dwMemoryAddress - pPeInfo->dwImageBase);

				dwOffset -= pCurNode->dwInsLen;
				*((PDWORD)(pCurNode->pFileAddress + 1)) = dwOffset;
				//花指令跳转到目的地址
				dwOffset = (pCurNode->dwGotoMemoryAddress - pPeInfo->dwImageBase) \
					- pObjectPE->OffsetToRVA((DWORD)lpCurBuf - dwPeFileAddr);

				dwOffset -= pCurNode->dwInsLen;
				*((PDWORD)(lpCurBuf + 1)) = dwOffset;
				*lpCurBuf = 0xE9;

				lpCurBuf += 0x5;
				pCurNode->bConfused = TRUE;

				//dwCurSize = 0x5;

			}//if-else

			//扣除使用的空间大小
			//RandomMod 返回的dwCurSize 包含花指令末地址跳转指令的长度
			dwRemainSize -= dwCurSize;
			
		}//if

		//每个节点有1/3的概率被抽取
		pCurNode = pCurNode->pNext;
	
	}//while

	return TRUE;
}


//////////////////////////////////////////////////////////////////////////
//	获取花指令模板的缓冲区和长度
//	参数：
//	LPWSTR szSelected		- 指定模板的绝对路径
//	PDWORD pdSizeOfMod		-[out]该模块的大小
//	返回值：
//	包含数据的缓冲区，失败返回NULL
//////////////////////////////////////////////////////////////////////////

LPBYTE	GetSelectedModAddr(LPWSTR szSelected, PDWORD pdSizeOfMod)
{
	if (szSelected == NULL)
		return NULL;

	DWORD	dwFileSize;
	DWORD	dwNumOfByteRead;
	HANDLE	hFile = CreateFile(szSelected, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	LPBYTE	pFileBuf;
	LPBYTE	pRetnBuf;

	if (hFile == NULL)
		return NULL;

	dwFileSize = GetFileSize(hFile, NULL);

	pFileBuf = new BYTE[dwFileSize];

	ZeroMemory(pFileBuf, dwFileSize);

	ReadFile(hFile, pFileBuf, dwFileSize, &dwNumOfByteRead, NULL);
	
	CloseHandle(hFile);

	*pdSizeOfMod = *((PDWORD)pFileBuf);

	pFileBuf += sizeof(DWORD);

	//重新复制数据，方便后续操作释放空间
	dwFileSize = *pdSizeOfMod;

	if (dwFileSize % 10)
	{
		dwFileSize = (dwFileSize / 10 + 1) * 10;
	}

	pRetnBuf = new BYTE[dwFileSize];

	ZeroMemory(pRetnBuf, dwFileSize);

	CopyMemory(pRetnBuf, pFileBuf, *pdSizeOfMod);

	delete (pFileBuf - sizeof(DWORD));

	return pRetnBuf;
}


//////////////////////////////////////////////////////////////////////////
//	随机获取一个花指令模板，若获取的模板空间大于当前剩余空间，则 \
//	采用顺序遍历，获取当前最少占用空间的模板，若仍找不到，返回NULL
//	参数：
//	LPWSTR szModPrefix		- 模块绝对路径的前缀
//	DWORD dwNumOfMod		- 模板数量
//	PDWORD pdRemainSize		- [in&out]当前剩余空间
//	PDWORD	pdArrayMod		- 模板大小的数组
//	PDWORD	pdCurSize		- [out]当前选中模板的大小
//	返回值：
//	若成功，则返回模板的缓冲区，否则返回NULL
//////////////////////////////////////////////////////////////////////////

LPBYTE	RandomMod(LPWSTR szModPrefix, DWORD dwNumOfMod, PDWORD pdRemainSize, PDWORD	pdArrayMod,
	PDWORD	pdCurSize)
{
	WCHAR	szTemp[MAX_PATH];
	DWORD	dwSize;
	LPBYTE	pFileBuF;
	DWORD	dwLowsetIndex;
	DWORD	dwTempVal;

	if (szModPrefix == NULL)
		return NULL;

	ZeroMemory(szTemp, sizeof(WCHAR)*MAX_PATH);
	wsprintf(szTemp, L"%s%d", szModPrefix, rand()%dwNumOfMod);

	pFileBuF = GetSelectedModAddr(szTemp, &dwSize);

	if (dwSize + 5 <= *pdRemainSize)
	{
		*pdCurSize = dwSize;
		return pFileBuF;
	}

	delete pFileBuF;
	


	for (DWORD dwIndex = 0; dwIndex < dwNumOfMod; dwIndex++)
	{
		if (dwIndex == 0)
		{
			dwTempVal = pdArrayMod[dwIndex];
			dwLowsetIndex = dwIndex;
			continue;
		}

		if (dwTempVal > pdArrayMod[dwIndex])
		{
			dwLowsetIndex = dwIndex;
			dwTempVal = pdArrayMod[dwIndex];
		}
	}


	//说明指令只够放下n个跳转指令，n不确定
	if (dwTempVal + 5 > *pdRemainSize)
	{
		*pdCurSize = 0x5;
		return NULL;
	}


	ZeroMemory(szTemp, sizeof(WCHAR)*MAX_PATH);
	wsprintf(szTemp, L"%s%d", szModPrefix, dwLowsetIndex);

	pFileBuF = GetSelectedModAddr(szTemp, &dwSize);

	//*pdRemainSize -= (dwTempVal + 5);
	*pdCurSize = dwTempVal;

	return pFileBuF;

}


//////////////////////////////////////////////////////////////////////////
//	将导入表解析，提取关键信息放入节点中，供后续"函数识别"模块使用
//	参数：
//	COperationPE* pObjectPE		- 目标程序的PE操作类指针
//	PEInfo stcPeInfo			- 目标程序的PE关键信息结构体
//	返回值：
//	返回链表头，否则NULL
//////////////////////////////////////////////////////////////////////////

pImport_Node	DrawIATNode(COperationPE* pObjectPE, pPEInfo pPeInfo)
{

	if (pObjectPE == NULL || pPeInfo == NULL)
		return NULL;

	PIMAGE_THUNK_DATA			pThunk, pTempThunk;
	PIMAGE_IMPORT_BY_NAME		pImportByName;
	DWORD						dwIndex;
	DWORD						dwCounter;
	PDWORD						pFunNum;
	CHAR*						szDllName;
	CHAR*						szFunName;
	PIMAGE_IMPORT_DESCRIPTOR	pImport;
	DWORD						dwFileAddr;
	pImport_Node				pImpCodeHeader = NULL, *pTempCode = &pImpCodeHeader;


	dwFileAddr = pObjectPE->GetFileAddr();
	
	pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pObjectPE->RVAToOffset(pPeInfo->stcPEImportDir.VirtualAddress)
		+ dwFileAddr);


	while (pImport->Name)
	{
		*pTempCode = new Import_Node;

		//复制模块名
		szDllName = (CHAR*)(pObjectPE->RVAToOffset(pImport->Name) + dwFileAddr);

		(*pTempCode)->szDllName = new CHAR[strlen(szDllName) + 1];

		strncpy((*pTempCode)->szDllName, szDllName, strlen(szDllName) + 1);

		//计算内存地址和文件地址
		(*pTempCode)->dwIATMemoryAddr = pImport->FirstThunk + pPeInfo->dwImageBase;

		(*pTempCode)->dwIATFileAddr = dwFileAddr + pObjectPE->RVAToOffset(pImport->FirstThunk);


		//做特殊处理
		if (pImport->OriginalFirstThunk == 0)
		{
			pThunk = (PIMAGE_THUNK_DATA)(dwFileAddr + pObjectPE->RVAToOffset(pImport->FirstThunk));
		}
		else
		{
			pThunk = (PIMAGE_THUNK_DATA)(dwFileAddr + pObjectPE->RVAToOffset(pImport->OriginalFirstThunk));
		}

		//计算项数
		pTempThunk = pThunk;
		dwCounter = 0;
		
		while (pTempThunk->u1.AddressOfData)
		{
			dwCounter++;
			pTempThunk++;
		}
		

		//生成函数名表
		(*pTempCode)->dwNumOfItem = dwCounter;

		(*pTempCode)->pdFunTable = new PCHAR[dwCounter];

		ZeroMemory((*pTempCode)->pdFunTable, sizeof(PCHAR)*dwCounter);

		dwIndex = 0;


		while (pThunk->u1.AddressOfData)
		{

			if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
			{//序号直接以0处理
				(*pTempCode)->pdFunTable[dwIndex] = 0x0;
			}
			else
			{//字符串
				pImportByName = (PIMAGE_IMPORT_BY_NAME)(pObjectPE->RVAToOffset(pThunk->u1.AddressOfData)\
					+ dwFileAddr);

				szFunName = (CHAR*)new BYTE[strlen(pImportByName->Name) + 1];
				
				CopyMemory(szFunName, pImportByName->Name, strlen(pImportByName->Name) + 1);

				(*pTempCode)->pdFunTable[dwIndex] = (PCHAR)szFunName;

			}//if - else

			dwIndex++;
			pThunk++;

		}//while


		(*pTempCode)->pNext = NULL;

		pTempCode = &((*pTempCode)->pNext);

		pImport++;
	}//while

	return pImpCodeHeader;
}


//////////////////////////////////////////////////////////////////////////
//	分析Displacement，是否位于IAT中，若位于，则找出其模块名与函数名
//	参数：
//	pImport_Node pImpHeader		- 链表头
//	LPBYTE  pFileAddr			- 下一跳数据，用udis86分析是否为FF25
//	PDWORD	pdIndex				-[out]该节点的函数表中对应函数名的索引
//	返回值：
//	返回所属模块的节点与其函数名索引,否则NULL
//////////////////////////////////////////////////////////////////////////

pImport_Node	AnalyseDisp(pImport_Node pImpHeader, LPBYTE pFileAddr,  PDWORD pdIndex)
{

	if (pFileAddr == NULL || pImpHeader == NULL)
		return NULL;

	pImport_Node	pImpTemp = pImpHeader;
	DWORD			dwMemAddrEnd;		
	DWORD			dwFileAddrEnd;
	DWORD			dwDisp;
	ud_t			ud_obj;
	LPBYTE			pCurInpPtr;
	

	ud_init(&ud_obj);
	ud_set_input_buffer(&ud_obj, pFileAddr, 0x6);
	ud_set_mode(&ud_obj, 32);
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);

	while (ud_disassemble(&ud_obj) != 0)
	{
		if (ud_obj.mnemonic == UD_Iinvalid)
			return NULL;

		switch (ud_obj.mnemonic)
		{
		case UD_Ijmp:
			pCurInpPtr = (LPBYTE)ud_insn_ptr(&ud_obj);
			if (pCurInpPtr[0] == 0xFF && pCurInpPtr[1] == 0x25)
			{//FF25 - JMP 跳转，直接提取其disp
				dwDisp = ud_obj.operand[0].lval.udword;
			}
			break;
		default:
			return NULL;
		}//switch

	}//while

	

	while (pImpTemp)
	{
		dwFileAddrEnd	= pImpTemp->dwIATFileAddr + 4 * (pImpTemp->dwNumOfItem - 1);
		dwMemAddrEnd	= pImpTemp->dwIATMemoryAddr + 4 * (pImpTemp->dwNumOfItem -1);

		if (dwDisp >= pImpTemp->dwIATMemoryAddr && dwDisp <= dwMemAddrEnd)
		{
			*pdIndex = (dwDisp - pImpTemp->dwIATMemoryAddr) / 4;

			break;
		}

		pImpTemp = pImpTemp->pNext;
	}


	return pImpTemp;
}


//////////////////////////////////////////////////////////////////////////
//	释放链表
//	参数：
//	pCode_Flow_Node pHeader		- 链表头
//////////////////////////////////////////////////////////////////////////

VOID	ReleaseCodeFlow(pCode_Flow_Node pHeader)
{
	if (pHeader == NULL)
		return;

	pCode_Flow_Node pTemp;

	while (pHeader)
	{
		pTemp = pHeader->pNext;

	/*	if (pHeader->pImpNode)
		{
			delete pHeader->pImpNode->pdFunTable;
			delete pHeader->pImpNode;
		}*/

		delete pHeader;
		pHeader = pTemp;
	}

}


//////////////////////////////////////////////////////////////////////////
//	解析样本文件，以数组方式保存
//	参数：
//	LPWSTR			szSample		- 样本的文件路径
//	PDWORD			pdTotalCtr		- 信息块的数量
//	返回值：
//	返回数组的起始地址，否则NULL
//////////////////////////////////////////////////////////////////////////


pSample_Array	AnalyseSample(LPWSTR szSample, PDWORD	pdTotalCtr)
{
	HANDLE				hFile;
	LPBYTE				pFileBuf;
	DWORD				dwFileSize;
	DWORD				dwNumOfBytesRead;
	DWORD				dwNumOfBlock;			//信息块的数量
	DWORD				dwLenOfFunc;
	DWORD				dwTotalCtr;
	pSample_Array		pSample;
	
	if (wcslen(szSample)== 0x0)
	{
		return NULL;
	}

	hFile = CreateFile(szSample, GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);


	if (hFile == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}

	dwFileSize = GetFileSize(hFile, NULL);

	pFileBuf = new BYTE[dwFileSize];

	ZeroMemory(pFileBuf, dwFileSize);

	ReadFile(hFile, pFileBuf, dwFileSize, &dwNumOfBytesRead, NULL);

	if (   *((PDWORD)pFileBuf)     != SIGNATURE_LOG )
	{
		CloseHandle(hFile);
		return NULL;
	}

	pFileBuf += sizeof(DWORD);

	dwNumOfBlock = *((PDWORD)pFileBuf);

	
	pSample = new Sample_Array[dwNumOfBlock];

	ZeroMemory(pSample, sizeof(Sample_Array)* dwNumOfBlock);


	for (DWORD dwIndex = 0; dwIndex < dwNumOfBlock ; dwIndex++)
	{
		pFileBuf += sizeof(DWORD);

		dwLenOfFunc = strlen((PCHAR)pFileBuf);

		pSample[dwIndex].szFunc = (PCHAR)new BYTE[dwLenOfFunc + 1];

		strncpy_s(pSample[dwIndex].szFunc, dwLenOfFunc +1, (PCHAR)pFileBuf, dwLenOfFunc + 1);
	
		pFileBuf += (dwLenOfFunc + 1);

		pSample[dwIndex].dwInvokedCtr = *((PDWORD)pFileBuf);

		//dwTotalCtr += pSample[dwIndex].dwInvokedCtr;

	}

	*pdTotalCtr = dwNumOfBlock;

	CloseHandle(hFile);

	return pSample;
	
}


//////////////////////////////////////////////////////////////////////////
//	随机函数总接口
//	该随机函数会根据当前乱序节点是否为调用外部函数，若是的话，则调出样本数据进行
//	匹配，匹配成功后，会适当的调整被乱序的概率
//	若没有调用外部函数，则按最低概率来处理
//	参数：
//	pSample_Array			pSampleArray	- 样本文件数组的指针
//	DWORD					dwTotalCtr		- 信息块的数量
//	pImport_Node			pImpNode		- 导入表节点信息
//	DWORD					dwFuncIndex		- 函数表中的索引
//	返回值：
//	若按随机概率被抽到，则返回TRUE, or else
//////////////////////////////////////////////////////////////////////////

BOOL	RandomProbability(pSample_Array pSampleArray, DWORD dwTotalCtr, pImport_Node pImpNode, DWORD dwFuncIndex)
{
	WCHAR	szTest[MAX_PATH];
	static DWORD	dwTime = 0;

	if (pImpNode == NULL || pSampleArray == NULL)
	{//按最低概率1/4处理
		 
		srand(time(NULL) + dwTime);

		dwTime++;

		if (rand() % 16 < 4)
			return TRUE;
		else
			return FALSE;
	}

	//该指令为调用外部函数
	DWORD	dwInvokedTotalCtr;
	BOOL	bInvoked = FALSE;			//是否被调用了
	DWORD	dwIndex;

	for (dwIndex = 0; dwIndex < dwTotalCtr ; dwIndex++)
	{
		if (StrCmpA(pSampleArray[dwIndex].szFunc, pImpNode->pdFunTable[dwFuncIndex]) == NULL)
		{
			bInvoked = TRUE;
			break;
		}
	}


	if (bInvoked == FALSE)
	{//没有在测试中被调用到，直接按1/3处理
		srand(time(NULL));
		if (rand() % 9 < 3)
			return TRUE;
		else
			return FALSE;
	}

	dwInvokedTotalCtr = CalcTotalInvokedCtr(pSampleArray, dwTotalCtr);

	DWORD	dwCurApiInvokedCtr;
	DWORD	dwNumerator;			//分子
	DWORD	dwDenominator;			//分母


	dwCurApiInvokedCtr = pSampleArray[dwIndex].dwInvokedCtr;

	// 当前API调用次数 / 总调用次数  + 1/3
	
	dwDenominator = 3 * dwInvokedTotalCtr;
	dwNumerator = dwInvokedTotalCtr + 3 * dwCurApiInvokedCtr;

	if (dwNumerator >= dwDenominator)
	{
		//分子大于分母，直接通行证
		return TRUE;
	}

	if (rand() % dwDenominator < dwNumerator)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}

}

//////////////////////////////////////////////////////////////////////////
//	计算出样本数据中，调用的总次数，用以计算每一个API的调用占比
//	参数：
//	pSample_Array		pSampleArray		- 样本数组
//	DWORD				dwTotalCtr			- 数组长度
//	返回值：
//	成功返回调用总次数，否则 -1
//////////////////////////////////////////////////////////////////////////

DWORD	CalcTotalInvokedCtr(pSample_Array pSampleArray, DWORD dwTotalCtr)
{
	DWORD	dwTotalInvokedCtr = 0;

	if (pSampleArray == NULL)
	{
		return -1;
	}


	for (DWORD dwIndex = 0; dwIndex < dwTotalCtr ; dwIndex++)
	{
		dwTotalInvokedCtr += pSampleArray[dwIndex].dwInvokedCtr;
	}

	return dwTotalInvokedCtr;


}

//////////////////////////////////////////////////////////////////////////
//	释放样本数据
//////////////////////////////////////////////////////////////////////////

VOID	ReleaseSampleArray(pSample_Array pSampleArray, DWORD dwTotalCtr)
{
	if (pSampleArray == NULL)
		return;


	for (DWORD dwIndex = 0; dwIndex <dwTotalCtr ; dwIndex++)
	{
		delete pSampleArray[dwIndex].szFunc;
	}

	delete pSampleArray;


}
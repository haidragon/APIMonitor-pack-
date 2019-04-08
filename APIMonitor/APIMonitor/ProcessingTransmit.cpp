#include "stdafx.h"
#include "ProcessingTransmit.h"




ProcessingList::ProcessingList()
{//为Modlist申请内存空间
	m_pModList		= (lpModList)VirtualAlloc(NULL, sizeof(ModList) * LIST_INC, MEM_COMMIT, PAGE_READWRITE);
	m_dwModListLen	= LIST_INC;
	ZeroMemory(m_pModList, LIST_INC * sizeof(ModList));
	m_pLog			= NULL;
}

ProcessingList::~ProcessingList()
{

	delete[] m_pModList;
}



//////////////////////////////////////////////////////////////////////////
//	添加模块信息至对应的List位置中，插入数组中的指定位置
//	参数：
//	lpPacketModInfo		lpData			-	指向一个模块信息的结构体
//////////////////////////////////////////////////////////////////////////

BOOL ProcessingList::AddModInfo(lpPacketModInfo lpData)
{
	DWORD	dwModIndex = lpData->dwModIndex;

	//先判断ModIndex是不是在范围之内
	if (lpData->dwModIndex >= m_dwModListLen)
	{
		lpModList	pTemp;
		//位置不够，要扩展数组长度
		pTemp = (lpModList)VirtualAlloc(NULL, sizeof(ModList) * (m_dwModListLen + LIST_INC), MEM_COMMIT, PAGE_READWRITE);
		
		if (!pTemp)	return FALSE;

		ZeroMemory(pTemp, sizeof(ModList) * (m_dwModListLen + LIST_INC));

		CopyMemory(pTemp, m_pModList, sizeof(ModList)* m_dwModListLen);

		VirtualFree(m_pModList, 0, MEM_RELEASE);

		m_pModList = pTemp;

		m_dwModListLen += LIST_INC;
	}

	
	CopyMemory(&m_pModList[dwModIndex], lpData, sizeof(PacketModInfo));
	
	//激活该模块在表中索引的使用
	m_pModList[dwModIndex].bActive = TRUE;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//	将该Api信息添加到Modlist和其apilist中
//	参数：
//	lpPacketApiInfo				lpData	 - 保存API信息的结构体指针
//////////////////////////////////////////////////////////////////////////

BOOL	ProcessingList::AddApiInfo(lpPacketApiInfo lpData)
{
	DWORD				dwModIndex		= lpData->dwModIndex;
	DWORD				dwApiIndex		= lpData->dwApiIndex;
	lpPacketApiInfo		lpApiList		= NULL;
	DWORD				dwApiListLen;
	
	if (!lpData)		return	FALSE;

	if (m_pModList[dwModIndex].lpApiList == NULL)
	{
		m_pModList[dwModIndex].lpApiList = (lpPacketApiInfo)VirtualAlloc(NULL, sizeof(PacketApiInfo) * LIST_INC,
			MEM_COMMIT, PAGE_READWRITE);;
		m_pModList[dwModIndex].dwApiListLen		= LIST_INC;

		ZeroMemory(m_pModList[dwModIndex].lpApiList, sizeof(PacketApiInfo) * LIST_INC);
	}

	//数组空间不足，需要扩大
	if (m_pModList[dwModIndex].dwApiListLen <= lpData->dwApiIndex)
	{
		dwApiListLen = m_pModList[dwModIndex].dwApiListLen;
		lpApiList = (lpPacketApiInfo)VirtualAlloc(NULL, sizeof(PacketApiInfo) * (dwApiListLen + LIST_INC),
					MEM_COMMIT, PAGE_READWRITE);

		if (!lpApiList)	return FALSE;

		m_pModList[dwModIndex].dwApiListLen += LIST_INC;
		
		ZeroMemory(lpApiList, sizeof(PacketApiInfo) * (dwApiListLen + LIST_INC));

		CopyMemory(lpApiList, m_pModList[dwModIndex].lpApiList, sizeof(PacketApiInfo) * dwApiListLen);

		VirtualFree(m_pModList[dwModIndex].lpApiList, 0, MEM_RELEASE);

		m_pModList[dwModIndex].lpApiList = lpApiList;
	}

	lpApiList = m_pModList[dwModIndex].lpApiList;

	CopyMemory(&lpApiList[dwApiIndex], lpData, sizeof(PacketApiInfo));

	lpApiList[dwApiIndex].bActive = TRUE;

	return	TRUE;
}


//////////////////////////////////////////////////////////////////////////
//	数据包过滤，分派函数
//	参数：
//	lpPacketInfo		lpData - 数据包缓冲区
//	返回值：消息类型，使外部调用函数可以根据该类型实现UI更新
//////////////////////////////////////////////////////////////////////////

DWORD	ProcessingList::GetMsgInfo(lpPacketInfo	lpData)
{
	WCHAR				szTrap[MAX_BUF_SIZE];
	lpTrapInfo			lpCurTrap;

	switch (lpData->dwType)
	{
	case MOD_MSG:	//模块信息
		AddModInfo((lpPacketModInfo)lpData->Data);
		OutputDebugString(L"模块添加OK");
		break;
	case API_MSG:	//Api信息
		AddApiInfo((lpPacketApiInfo)lpData->Data);
		break;
	case TRAP_MSG:	//Api触发信息
		ZeroMemory(szTrap, sizeof(WCHAR)*MAX_BUF_SIZE);
		lpCurTrap = (lpTrapInfo)lpData->Data;
		
		wsprintf(szTrap, L"Mod:%s ApiIndex:%s RetAddr:%x", m_pModList[lpCurTrap->dwModIndex].szModName,
			m_pModList[lpCurTrap->dwModIndex].lpApiList[lpCurTrap->dwApiIndex].szApiName, 
			lpCurTrap->dwRetAddr);
		

		break;
	default:
		break;
	}

	return lpData->dwType;

}


//////////////////////////////////////////////////////////////////////////
//	对DLL段的某个模块发送Hook或者UnHook的指令
//	参数：
//	HANDLE		hPipe		- 管道句柄
//	WCHAR*		szModName	- 模块名
//	BOOL		bHook		- 是否HOOK
//////////////////////////////////////////////////////////////////////////

VOID	ProcessingList::SendHookMod(HANDLE hPipe, WCHAR* szModName, BOOL bHook)
{
	lpPacketInfo	lpPacket = NULL;
	HookMod			stcHookInfo;
	DWORD			dwTotalLength;
	DWORD			dwBytesOfWritten;

	for (DWORD dwIndex = 0; dwIndex < m_dwModListLen; dwIndex++)
		if (wcscmp(szModName, m_pModList[dwIndex].szModName) == 0)
		{
			stcHookInfo.bHook = bHook;
			stcHookInfo.dwModIndex = dwIndex;
			dwTotalLength = sizeof(HookMod) + sizeof(PacketInfo);
			lpPacket = (lpPacketInfo)new BYTE[dwTotalLength];
			lpPacket->dwType = HOOK_MSG;
			lpPacket->dwLegth = sizeof(HookMod);
			CopyMemory(lpPacket->Data, &stcHookInfo, lpPacket->dwLegth);
			
			WriteFile(hPipe, lpPacket, dwTotalLength, &dwBytesOfWritten, NULL);
			break;
		}

}


//////////////////////////////////////////////////////////////////////////
//	给出调用地址，获取其调用的模块名
//	参数：
//	DWORD dwInvokedAddr	 - 调用地址
//	返回值：	全局ModList中的ModName地址
//////////////////////////////////////////////////////////////////////////

WCHAR*	ProcessingList::GetInvokedModName(DWORD dwInvokedAddr)
{
	for (DWORD	dwIndex = 0; dwIndex < m_dwModListLen; dwIndex++)
	{
		if (m_pModList[dwIndex].dwBaseAddr <= dwInvokedAddr && 
			dwInvokedAddr < (m_pModList[dwIndex].dwBaseAddr + m_pModList[dwIndex].dwImageSize))
		{
			return m_pModList[dwIndex].szModName;
		}
	}

	return NULL;
}


//////////////////////////////////////////////////////////////////////////
//	获取指定所以的Api名称
//	参数：
//	DWORD dwModIndex	 - 模块索引
//	DWORD dwApiIndex	 - Api索引
//	返回值：	Api名称的地址
//////////////////////////////////////////////////////////////////////////

WCHAR*	ProcessingList::GetApiName(DWORD dwModIndex, DWORD dwApiIndex)
{
	if (dwApiIndex >= m_pModList[dwModIndex].dwApiListLen)	return NULL;
	return m_pModList[dwModIndex].lpApiList[dwApiIndex].szApiName;
}


//////////////////////////////////////////////////////////////////////////
//	发送过滤Api的数据包
//	参数：
//	HANDLE			hPipe		- 管道句柄
//	DWORD			dwModIndex	- 模块索引
//	DWORD			dwApiIndex	- Api索引
//	BOOL			bFiltered	- 是否过滤
//////////////////////////////////////////////////////////////////////////

VOID	ProcessingList::SendFilteredApi(HANDLE hPipe, DWORD dwModIndex, DWORD dwApiIndex, BOOL bFiltered)
{
	lpPacketInfo	lpPacket = NULL;
	FilteredInfo	stcApi;
	DWORD			dwTotalLength;
	DWORD			dwBytesOfWritten;


	stcApi.dwModIndex = dwModIndex;
	stcApi.dwApiIndex = dwApiIndex;
	stcApi.bFilterd		= bFiltered;

	dwTotalLength = sizeof(FilteredInfo) + sizeof(PacketInfo);
	lpPacket = (lpPacketInfo)new BYTE[dwTotalLength];
	lpPacket->dwType = FILTER_MSG;
	lpPacket->dwLegth = sizeof(FilteredInfo);
	CopyMemory(lpPacket->Data, &stcApi, lpPacket->dwLegth);

	WriteFile(hPipe, lpPacket, dwTotalLength, &dwBytesOfWritten, NULL);
	
}



//////////////////////////////////////////////////////////////////////////
//	将自身模块调用的函数统计进列表中，计算累积次数，长度不足自动拓展
//	参数：
//	CHAR* szApiName - 函数名
//////////////////////////////////////////////////////////////////////////


VOID	ProcessingList::InsertOfBinary(CHAR* szApiName)
{
	DWORD			dwIndex;
	lpLogBinary		lpTemp;

	if (m_pLog == NULL)
	{
		m_pLog = (lpLogBinary)VirtualAlloc(NULL, LIST_INC * sizeof(LogBinary), MEM_COMMIT, PAGE_READWRITE);
		ZeroMemory(m_pLog, LIST_INC * sizeof(LogBinary));
		m_dwLogListLen = LIST_INC;
	}

	for (dwIndex = 0; dwIndex < m_dwLogListLen; dwIndex++)
	{
		if (strlen( m_pLog[dwIndex].szApiName) == 0)	break;
		
		if (strcmp(szApiName, m_pLog[dwIndex].szApiName) == 0)
		{
			m_pLog[dwIndex].dwCount++;
			return;
		}
	}

	//列表长度不足，需扩展
	if (dwIndex == m_dwLogListLen)
	{
		m_dwModListLen += LIST_INC;
		lpTemp = (lpLogBinary)VirtualAlloc(NULL, m_dwModListLen  * sizeof(LogBinary), MEM_COMMIT, PAGE_READWRITE);
		ZeroMemory(lpTemp, sizeof(LogBinary)*m_dwModListLen);
		CopyMemory(lpTemp, m_pLog, dwIndex * sizeof(LogBinary));
		VirtualFree(m_pLog, 0, MEM_RELEASE);
		m_pLog = lpTemp;
	}

	//插入新成员
	strcpy_s(m_pLog[dwIndex].szApiName, szApiName);
	m_pLog[dwIndex].dwCount++;


}


//////////////////////////////////////////////////////////////////////////
//	返回封装数据的缓冲区和整个列表的大小(bytes)
//	参数：
//	DWORD*		pdSize		- [out]该列表的字节大小
//	返回值：	保存log的二进制缓冲区
//////////////////////////////////////////////////////////////////////////

DWORD	ProcessingList::GetLogInfo(DWORD* pdSize)
{
	DWORD		dwIndex;
	LPBYTE		lpData = NULL;
	DWORD		dwOffset = 0;

	if (m_pLog == NULL)
	{
		*pdSize = 0x0;
		return NULL;
	}

	for (dwIndex = 0; dwIndex < m_dwLogListLen; dwIndex++)
	{
		if (strlen(m_pLog[dwIndex].szApiName) == 0)	break;
	}

	// Signature | ItemCount | szApiname1 | invokedCount | szApiname2 |invokedCount
	*pdSize = sizeof(DWORD) +  sizeof(DWORD) +   dwIndex * sizeof(LogBinary) ;

	lpData = (LPBYTE)VirtualAlloc(NULL, *pdSize, MEM_COMMIT, PAGE_READWRITE);

	//复制Signature
	*(PDWORD)lpData = SIGNATURE_LOG;
	dwOffset += sizeof(DWORD);

	//复制ItemCount
	CopyMemory(lpData+ dwOffset, &dwIndex, sizeof(DWORD));
	dwOffset += sizeof(DWORD);

	for (DWORD i = 0; i < dwIndex; i++)
	{
		strcpy_s((CHAR*)(lpData + dwOffset),  strlen(m_pLog[i].szApiName)+1,  m_pLog[i].szApiName);
		dwOffset += (strlen(m_pLog[i].szApiName) + 1);
		CopyMemory(lpData + dwOffset, &m_pLog[i].dwCount, sizeof(DWORD));
		dwOffset += sizeof(DWORD);
	}
	
	*pdSize = dwOffset;

	return (DWORD)lpData;

}
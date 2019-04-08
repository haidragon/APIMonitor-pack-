#pragma once

#include <windows.h>
#include <udis86.h>
#include <time.h>
#include "OperationPE.h"

//跳转和call指令的链表结构

#define JmpIns_Type_Jcc			0x0
#define JmpIns_Type_Jmp			0x1
#define JmpIns_Type_Call		0x2

typedef struct _Import_Node Import_Node, *pImport_Node;

typedef struct _Code_Flow_Node
{
	struct _Code_Flow_Node *pNext;					//下一个节点
	BOOL					bGoDown;				//是否向下跳
	DWORD					dwBits;					//跳转范围
	DWORD					dwType;					//指令类型
	BOOL					bFar;					//是否是远跳
	DWORD					dwMemoryAddress;		//当前内存地址
	LPBYTE					pFileAddress;			//当前文件地址
	DWORD					dwGotoMemoryAddress;	//跳转后的内存地址
	LPBYTE					pGotoFileAddress;		//跳转后的文件地址
	DWORD					dwInsLen;				//指令长度
	pImport_Node			pImpNode;				//在IAT中的节点信息
	DWORD					dwFunIndex;				//节点函数表的索引
	DWORD					dwFinalMemoryAddress;	//花指令的内存地址
	DWORD					dwFinalFileAddress;		//花指令的文件地址
	BOOL					bConfused;				//是否乱序
	union
	{
		BYTE bOffset;
		WORD wOffset;
		DWORD dwOffset;
	};//偏移
}Code_Flow_Node, *pCode_Flow_Node;


typedef struct _Import_Node
{
	CHAR*					szDllName;			//模块名
	DWORD					dwIATMemoryAddr;	//IAT的内存地址
	DWORD					dwIATFileAddr;		//IAT的文件地址
	DWORD					dwNumOfItem;		//导入函数的项数
	PCHAR *					pdFunTable;			//函数名表
	struct _Import_Node*	pNext;
}Import_Node, *pImport_Node;



//样本文件所使用的存储结构
typedef	struct _Sample_Array
{
	DWORD	dwInvokedCtr;						//被调用的次数
	PCHAR	szFunc;								//函数名
}Sample_Array, *pSample_Array;



//////////////////////////////////////////////////////////////////////////
//	反汇编处理接口
//////////////////////////////////////////////////////////////////////////

pCode_Flow_Node DrawCodeFlow(COperationPE* pObjectPE, pPEInfo pPeInfo, CONST LPBYTE pStart, DWORD dwSize);

//////////////////////////////////////////////////////////////////////////
//	花指令模板文件接口
//////////////////////////////////////////////////////////////////////////

DWORD	CalcAverageVal(LPWSTR ConfigPath, LPWSTR ModPath, PDWORD pdModNum, PDWORD* pdArrayMod);
BOOL	GetConfigPath(LPWSTR ConfigPath, DWORD dwConfigSize);
DWORD	GetNumOfNode(pCode_Flow_Node pHeader);
BOOL	ConfuseCode(pCode_Flow_Node pHeader, 
		COperationPE* pObjectPE,
		pPEInfo pPeInfo,
		LPBYTE pNewSection,
		PIMAGE_SECTION_HEADER	pSecHeader,
		DWORD	dwNumOfMod,
		LPWSTR	szModPrefix,
		PDWORD	pdArrayMod,
		pSample_Array	pSampleArray,
		DWORD	dwTotalCtr);
LPBYTE	GetSelectedModAddr(LPWSTR szSelected, PDWORD pdSizeOfMod);
LPBYTE	RandomMod(LPWSTR szModPrefix, DWORD dwNumOfMod, PDWORD pdRemainSize, PDWORD	pdArrayMod,
	PDWORD	pdCurSize);

VOID	ReleaseCodeFlow(pCode_Flow_Node pHeader);


//////////////////////////////////////////////////////////////////////////
//		导入表处理接口
//////////////////////////////////////////////////////////////////////////

pImport_Node	DrawIATNode(COperationPE* pObjectPE, pPEInfo pPeInfo);
pImport_Node	AnalyseDisp(pImport_Node pImpHeader,LPBYTE pFileAddr, PDWORD pdIndex);


//////////////////////////////////////////////////////////////////////////
//	样本文件处理接口
//////////////////////////////////////////////////////////////////////////

#define			SIGNATURE_LOG				0x00005150

pSample_Array	AnalyseSample(LPWSTR szSample, PDWORD pdTotalCtr);
DWORD			CalcTotalInvokedCtr(pSample_Array pSampleArray, DWORD dwTotalCtr);
BOOL			RandomProbability(pSample_Array pSampleArray, DWORD dwTotalCtr,pImport_Node pImpNode,DWORD	dwFuncIndex);
VOID			ReleaseSampleArray(pSample_Array pSampleArray, DWORD dwTotalCtr);
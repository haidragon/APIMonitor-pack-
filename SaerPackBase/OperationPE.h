#pragma once

#include <Windows.h>
#include <string.h>
#include <stdlib.h>
#include <shlwapi.h>
#include <aplib.h>
#include <jcalg1.h>
#include <stdint.h>  
#pragma comment(lib,"aplib.lib")
#pragma comment(lib,"shlwapi.lib")


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

	//试验功能
	BOOL	bIsVirtualizeCode;		//代码虚拟化
	WCHAR	szSample[MAX_PATH];
}SelectionInfo, *PSelectionInfo;



typedef struct _PEInfo
{
	DWORD					dwOEP;				// 入口点
	DWORD					dwImageBase;		// 映像基址
	DWORD					dwSectionAlign;		// 内存对齐粒度
	DWORD					dwFileAlign;		// 文件对齐粒度
	DWORD					dwSizeOfImage;		// 镜像大小
	DWORD					dwNumOfSections;	// 节表数量
	PIMAGE_DATA_DIRECTORY	pDataDir;			// 数据目录指针
	PIMAGE_SECTION_HEADER	pSectionHeader;		// 区段表头部指针
	IMAGE_DATA_DIRECTORY	stcPERelocDir;		// 重定位表信息
	IMAGE_DATA_DIRECTORY	stcPEImportDir;		// 导入表信息
	IMAGE_DATA_DIRECTORY	stcPEResDir;		// 资源表信息
	IMAGE_DATA_DIRECTORY	stcPETlsDir;		// tls表信息
	IMAGE_DATA_DIRECTORY	stcIATDir;			// IAT信息
	DWORD					dwNewResAddr;		// 重构res后的地址（文件偏移），ReBuildRes的输出参数
	DWORD					dwNewResSize;		// 转移后的资源头+关键数据的大小 == 新资源区段的真实尺寸
	DWORD					dwResHeaderSize;	// 资源头的大小
	DWORD					dwTlsOffset;		// tls所在区段与代码段的距离（RVA）
	DWORD					dwTlsSectionRVA;	// tls所在区段的起始RVA
	BOOL					bIsDll;				// 是否为dll文件
	DWORD					dwDllName;			// 若是dll的话，则保存dll的name
	LPBYTE					pExportBuf;			// 此为导出表的备份数据，因为预处理会使导出表被加密，从而影响后面的shell植入操作
	PDWORD					pExpAddrOfName;		// 保存着导出表AddressOfName
	LPBYTE					pOriginalSecTable;	// 保存着旧的节表
	LPBYTE					pCompressInfo;		// 保存压缩信息的结构体数组
	BOOL					bTls;				// 是否存在tls段
	DWORD					dwTlsModStart;		// tls模板数据的起始VA
	DWORD					dwTlsModEnd;		// tls模板数据的末VA
	DWORD					dwTlsIndexValue;	// tls索引值
	DWORD					dwCodeBase;			// 代码段基址
	DWORD					dwCodeSize;			// 代码段大小（内存粒度）
	DWORD					dwCodeRawSize;		// 代码段的大小（文件粒度）
	DWORD					dwSizeOfHeader;		// 目标程序的PE头大小
	LPBYTE					pNewIATAddr;		// 转储IAT的地址
	DWORD					dwNewIATSize;		// 转储IAT的大小
	DWORD					dwOrigIATBase;		// 原始IAT所在段的起始RVA
	DWORD					dwOrigIATSize;		// 原始IAT所在段的长度
	LPBYTE					pNewRelocAddr;		// 转储重定位表的地址
	DWORD					dwNewRelocSize;		// 转储重定位表的大小
	DWORD					dwCodeMemCRC32;		// 代码段的CRC32值
}PEInfo , *pPEInfo;



class COperationPE
{
public:
	COperationPE();
	~COperationPE();
	


public:
	DWORD	RVAToOffset(DWORD	dwRVA);
	DWORD	OffsetToRVA(DWORD	dwRawPointer);
	BOOL	GetPEInfo(LPBYTE pFileBuf,DWORD dwFileSize, pPEInfo	pObjectPEInfo);
	LPBYTE	GetExpVarAddr(LPWSTR strVarName);
	LPBYTE	AddSection(LPWSTR strName, DWORD dwSize, DWORD dwCharac, PIMAGE_SECTION_HEADER pNewSection,  PDWORD pSizeOfRaw);
	VOID	RECReloc(DWORD dwLoadImageBase, PIMAGE_SECTION_HEADER	pObjectPeNewSection);
	VOID	SetOEP(DWORD dwOEP);
	VOID	SetDir(DWORD dwType, DWORD dwVirtualAddress, DWORD dwSize);
	VOID	CleanDir();
	VOID	FindSectionOfIAT(PDWORD dwIATBase, PDWORD  dwSize);
	VOID	ReBuildRes(pPEInfo pObjectPE);
	DWORD	FixRes(COperationPE* pObjectPE, pPEInfo pObjectPEInfo);
	BOOL	FindSectionOfTls(pPEInfo pObjectPEInfo, PDWORD dwTlsSectionStartRVA, PDWORD dwSectionRealSize);
	BOOL	ChangeModuleData(DWORD dwStartAddr, DWORD dwEndAddr, DWORD dwIndexValue);
	VOID	ReturnTlsModuleAddress(PDWORD dwStartAddr, PDWORD dwEndAddr, PDWORD dwIndexValue);
	VOID	GetExportBuf( pPEInfo pPeInfo);
	BOOL	RelocExportTable(DWORD dwNewExportRVA, PIMAGE_EXPORT_DIRECTORY	pNewExp);
	VOID	CompressSection(pPEInfo pObjectPE, PSelectionInfo pSelect);
	DWORD	AlignSize(DWORD dwSize, DWORD dwAlign);
	DWORD	MoveImportTable(DWORD dwNewAddr);
	BOOL	CleanImportTable();
	DWORD	MoveRelocTable(DWORD dwNewAddr);
	BOOL	CleanRelocTable();
	VOID	CalAndSaveCRC(DWORD dwFileSize);
	VOID	CalMemCRC(LPBYTE pCodeBase, DWORD dwSize, pPEInfo pObjectPE);
	DWORD	GetFileAddr();
	DWORD	GetFileRawSize();
private:
	DWORD	CalcuCRC(UCHAR *string, uint32_t size);
	VOID	MakeCRC32Table();
	LPBYTE	CompressDataOfAplib(LPBYTE pData, DWORD dwSize, PDWORD dwPackedSize);
	LPBYTE	ComressDataOfJCALG1(LPBYTE pData, DWORD dwSize, PDWORD dwPackedSize);
	DWORD	FindResourceHeader(LPBYTE pResHeaderAddr ,LPBYTE pResAddr,  DWORD	dwMinRVA);
	VOID	MoveObjectRes(LPBYTE pResAddr, DWORD dwType, LPBYTE pDataBuf, PDWORD dwBufSize);
	VOID	FixResDataEntry(LPBYTE	pNewResAddr, DWORD dwType,  DWORD dwCurrentRVA, DWORD dwDataOffset, PDWORD	dwReturnedDataSize);
private:
	DWORD				 m_dwFileDataAddr;	// 目标文件所在缓存区的地址
	DWORD				 m_dwFileDataSize;	// 目标文件大小
	PIMAGE_DOS_HEADER	 m_pDosHeader;		// DOS头指针
	PIMAGE_NT_HEADERS	 m_pNtHeader;		// NT头指针
	PEInfo				 m_stcPeInfo;		// PE关键信息
	BOOL				 m_bCRC32Table;		// 是否生成了CRC32表格
	uint32_t			 crc32_table[256];	// CRC32计算表格
};





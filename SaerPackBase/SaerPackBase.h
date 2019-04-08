// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 SAERPACKBASE_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// SAERPACKBASE_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifdef SAERPACKBASE_EXPORTS
#define SAERPACKBASE_API __declspec(dllexport)
#else
#define SAERPACKBASE_API __declspec(dllimport)
#endif

#include "OperationPE.h"
#include "CodeConfusedEngine.h"

typedef struct _SHELL_DATA
{
	DWORD					dwPEOEP;			//程序入口点
	DWORD					dwOldOEP;			//原程序OEP
	DWORD					dwImageBase;		//PE文件默认映像基址
	DWORD					dwIATSectionBase;	//IAT所在段基址
	DWORD					dwIATSectionSize;	//IAT所在段大小
	DWORD					dwCodeBase;			//代码段基址
	DWORD					dwCodeSize;			//代码段大小（内存粒度）
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


// 声明一个导出的API，共界面程序调用执行加壳操作
extern "C" SAERPACKBASE_API BOOL PackBase(LPWSTR strPath, PSelectionInfo pSelect);

// 加壳时会用到的函数声明
extern VOID		Pretreatment(LPBYTE pCodeStart, LPBYTE pCodeEnd, COperationPE* pObejctPE, pPEInfo pPeInfo, PSelectionInfo pSelect);
extern DWORD	Implantation( LPWSTR pFileName, DWORD dwFileBufSize, COperationPE* pObjectPE, PEInfo stcPeInfo, PSHELL_DATA pGlobalVar, PSelectionInfo pSelect);

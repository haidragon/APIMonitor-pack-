#pragma once
#include <windows.h>
#include "./src/detours.h"
#include <stddef.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include "ApiParam.h"
#include <Shlwapi.h>
#pragma comment(lib,"shlwapi.lib")


#define			MAX_NAME_LEN                100
#define			MOD_MSG						0x1
#define			API_MSG						0x2
#define			TRAP_MSG					0x3
#define			FINISH_MODMSG				0x4					//	该消息类型表示，模块数据和API数据已经传输完毕，UI可以进行生成工作
#define			FINISH_APIMSG				0x6						
#define			LIST_INC					50					//	数组增量
#define			LIST_API_INC				10					//	API数量基数
#define			FILTER_MSG					0x7					//	过滤指定的API
#define			HOOK_MSG					0x5					//	Hook指定的模块



typedef struct _ShellCode ShellCode, *lpShellCode;
typedef	struct _ApiInfo ApiInfo, *lpApiInfo;
typedef struct _ModInfo ModInfo, *lpModInfo;

//声明指令处理线程
DWORD  WINAPI ThreadProc(LPVOID lpPara);
//模拟主线程
DWORD  WINAPI ThreadProc2(LPVOID lpPara);
//连接管道
HANDLE ConnectToNamePipe(WCHAR* szNamePipe);


//扫描模块
BOOL	ScanModule();
BOOL	ScanModule2();


//过滤API
BOOL	FilterApi(WCHAR* szModName, WCHAR* szApiName);

//Hook与UnHook
VOID	ReHookModule(DWORD dwModIndex);
VOID	HookModule(DWORD dwModIndex);
BOOL	UnHookModule(DWORD dwModIndex);

//添加Mod信息
DWORD	AddModuleToList(DWORD dwBaseAddr, DWORD dwImageSize, WCHAR* szModName);

//申请该Mod的Api的节点信息
DWORD	AllocApiFromList(lpModInfo lpCurModNode);


//初始化ShellCode
VOID	InitApiShellStruct(lpShellCode lpShell);

//shellcode中的触发函数
 extern "C"	  VOID  __stdcall TrappedApiCall(DWORD dwModIndex, DWORD dwApiIndex, VOID* pStack);

//卸载Detour的Hook并且释放空间
BOOL UnHookAllApi();

//清理List空间
BOOL FreeListMemory();


//通信模块
VOID SendModInfo(lpModInfo lpCurModNode);
VOID SendApiInfo(lpApiInfo lpCurApiNode);
VOID SendTrapInfo(VOID* pStack, DWORD dwModIndex, DWORD dwApiIndex, WCHAR* szParam);
VOID SendFinish(DWORD	dwType);

//过滤判断函数
BOOL IsFilteredApi(DWORD dwModIndex, DWORD dwApiIndex);

#pragma   pack(1) 
//shellCode的结构体，便于构造
typedef struct _ShellCode
{
	BYTE   byPushadOpc;			// 0x60 pushad

	BYTE   byPushEsp;			// 0x54 push esp
	BYTE   byPushOpc2;			// 0x68 push (dword)
	DWORD  dwPushApiIndex;		// Api Index
	BYTE   byPushOpc1;			// 0x68 push (dword)
	DWORD  dwPushModIndex;		// Mod Index
	BYTE   byCallOpc;			// 0xE8 call (dword)
	DWORD  dwCallAddr;			// address of "TrappedApiCall"

	BYTE   byPopadOpc;			// 0x61 popad

	BYTE   byJmpOpcApi;			// 0xE9 jmp (dword)
	DWORD  dwJmpApiAddr;		// jmp to the real Api function
}ShellCode, *lpShellCode;





//模块信息结构体
typedef struct _ModInfo
{
	DWORD		dwBaseAddr;
	BOOL		bIsFiltered;
	DWORD		dwImageSize;
	DWORD		dwModIndex;
	WCHAR		szModName[MAX_NAME_LEN];
	DWORD		dwPrivateApiListIndex;			//	用于Api列表的索引
	DWORD		dwApiListLen;					//	当前Api列表的长度
	lpApiInfo	lpApiList;
	BOOL		bActive;						//	是否已经读取了api消息,该标志用于判断已经被hook过的模块，避免在重新申请和发送api消息给监控端
}ModInfo, *lpModInfo;

//api信息结构体
typedef	struct _ApiInfo
{
	DWORD			dwApiRealAddr;
	BOOL			bIsHooked;		
	BOOL			bIsFiltered;
	DWORD			dwModIndex;
	DWORD			dwApiIndex;
	DWORD			dwOridinal;							
	WCHAR			szApiName[MAX_NAME_LEN];
	lpShellCode		lpShellBuf;					//ShellCode
}ApiInfo, *lpApiInfo;


//过滤API的结构体
typedef struct  _FilteredInfo
{
	DWORD	dwModIndex;
	DWORD	dwApiIndex;
	BOOL	bFilterd;
}FilteredInfo, *lpFilteredInfo;





//////////////////////////////////////////////////////////////////////////
//			通信结构体
//////////////////////////////////////////////////////////////////////////

//封装模块信息的数据包结构体
typedef struct _PacketModInfo
{
	DWORD	dwBaseAddr;
	DWORD	dwModIndex;
	DWORD	dwImageSize;
	WCHAR	szModName[MAX_NAME_LEN];
}PacketModInfo, *lpPacketModInfo;



//封装Api信息的数据包结构体
typedef	struct _PacketApiInfo
{
	DWORD	dwApiRealAddr;
	DWORD	dwModIndex;
	DWORD	dwApiIndex;					//	Api在数组里面的索引
	DWORD	dwOridinal;					//	最高位为1的话，则视为以序号导出
	WCHAR	szApiName[MAX_NAME_LEN];	//	若有的话，则在数据包中包含，否则，不封装，为了节约空间
}PacketApiInfo, *lpPacketApiInfo;



//Api触发的数据包结构体
typedef struct _PacketTrapInfo
{
	DWORD	dwRetAddr;					// Api的返回地址
	DWORD	dwModIndex;	
	DWORD	dwApiIndex;
	//参数选项，待补充
	DWORD	dwLength;					//参数总长度
	BYTE	byPara[1];					//参数表,提取要注意顺序
}PacketTrapInfo, *lpPacketTrapInfo;


//数据包封装结构
typedef	struct _PacketInfo
{
	DWORD	dwType;						//类型，见宏定义x_MSG
	DWORD	dwLegth;					//数据长度
	BYTE	Data[1];					//数据缓冲区
}PacketInfo, *lpPacketInfo;


typedef struct _StringFilteredDllList
{
	WCHAR	szDllName[12];		//Dll名称前缀
	DWORD	dwCheckSize;		//匹配长度(意思是，不需要全部匹配，匹配头几个关键字即可过滤其一系列的Dll)
} StringFilteredDllList, *lpStringFilteredDllList;

//接收监控端HOOK指令的协议
typedef struct  _HookMod
{
	DWORD	dwModIndex;
	BOOL	bHook;
}HookMod, *lpHookMod;
#pragma once

#include <windows.h>

#define			MAX_BUF_SIZE				1024		//	消息接收的缓冲区大小
#define			MAX_NAME_LEN                50			//	API or MOD 名字长度
#define			MOD_MSG						0x1			//	模块消息类型
#define			API_MSG						0x2			//	API消息类型
#define			TRAP_MSG					0x3			//	API触发类型
#define			FINISH_MODMSG				0x4			//	该消息类型表示，模块数据和API数据已经传输完毕，UI可以进行生成工作
#define			HOOK_MSG					0x5			//	监控端对指定模块发送HOOK指令
#define			FINISH_APIMSG				0x6			//	指定模块的API数据已经传输完毕，可以UI显示	
#define			FILTER_MSG					0x7			//	过滤指定的API
#define			SIGNATURE_LOG				0x00005150

#define			FILE_DIR					L"HookRecord"


#define			LIST_INC					0x50		//	数组增量

#pragma   pack(1) 

//数据包封装结构
typedef	struct _PacketInfo
{
	DWORD	dwType;						//类型，见宏定义x_MSG
	DWORD	dwLegth;					//数据长度
	BYTE	Data[1];					//数据缓冲区
}PacketInfo, *lpPacketInfo;

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
	WCHAR	szApiName[MAX_NAME_LEN];	
	BOOL	bActive;					//	该API是否被激活
}PacketApiInfo, *lpPacketApiInfo;



//Api触发的数据包结构体
typedef struct _TrapInfo
{
	DWORD	dwRetAddr;						// Api的返回地址
	DWORD	dwModIndex;
	DWORD	dwApiIndex;
	//参数选项，待补充
	DWORD	dwLength;					//参数总长度
	BYTE	byPara[1];					//参数表,提取要注意顺序
}TrapInfo, *lpTrapInfo;


//过滤API的结构体
typedef struct  _FilteredInfo
{
	DWORD	dwModIndex;
	DWORD	dwApiIndex;
	BOOL	bFilterd;

}FilteredInfo, *lpFilteredInfo;


//类的操作结构体
typedef struct _ModList
{
	DWORD				dwBaseAddr;
	DWORD				dwModIndex;
	DWORD				dwImageSize;
	WCHAR				szModName[MAX_NAME_LEN];
	BOOL				bActive;						//代表该索引的模块是否被激活,默认为FALSE，目的给UI来判断是否可显示
	DWORD				dwApiListLen;					//链表长度
	lpPacketApiInfo		lpApiList;						//保存API链表的信息
}ModList, *lpModList;



//Mod Tree Ctl控件所使用的数据包结构
typedef struct  _HookMod
{
	DWORD	dwModIndex;
	BOOL	bHook;
}HookMod , *lpHookMod;



// 写入LogBunary二进制样本文件中的结构体
typedef struct _LogBinary
{
	CHAR	szApiName[MAX_NAME_LEN];	//自身模块调用的函数名
	DWORD	dwCount;					//调用次数
}LogBinary, *lpLogBinary;





class ProcessingList
{
public:
	ProcessingList();
	~ProcessingList();

	BOOL	AddModInfo(lpPacketModInfo	lpData);
	BOOL	AddApiInfo(lpPacketApiInfo	lpData);
	DWORD	GetMsgInfo(lpPacketInfo		lpData);
	VOID	SendHookMod(HANDLE hPipe, WCHAR* szModName,BOOL bHook);
	VOID	SendFilteredApi(HANDLE hPipe, DWORD dwModIndex, DWORD dwApiIndex, BOOL bFiltered);
	WCHAR*	GetInvokedModName(DWORD dwInvokedAddr);
	WCHAR*	GetApiName(DWORD dwModIndex, DWORD dwApiIndex);
	VOID	InsertOfBinary(CHAR* szApiName);
	DWORD	GetLogInfo(DWORD* pdSize);
	

public:
	lpModList		m_pModList;
	DWORD			m_dwModListLen;		//模块链表的长度
	lpLogBinary		m_pLog;				//二进制样本文件的数据指针
	DWORD			m_dwLogListLen;
};


#pragma once
#include "ProcessingTransmit.h"
#include "./src/detours.h"
#include <shlwapi.h>
#pragma comment(lib,"shlwapi.lib")
// CProcessOperator 对话框




class CProcessOperator : public CDialogEx
{
	DECLARE_DYNAMIC(CProcessOperator)

public:
	CProcessOperator(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CProcessOperator();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_PROC };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg			void OnBnClickedButtonOK();
	afx_msg			void OnBnClickedButtonOpen();
	WCHAR			szFile[MAX_PATH];
	BOOL			bStartedHook;		//是否一加载就HOOK SS文件中的API

};

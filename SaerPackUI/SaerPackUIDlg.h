
// SaerPackUIDlg.h : 头文件
//

#pragma once


// CSaerPackUIDlg 对话框

#include "Config.h"




class CSaerPackUIDlg : public CDialogEx
{
// 构造
public:
	CSaerPackUIDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SAERPACKUI_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonOpen();
	afx_msg void OnBnClickedButtonPack();
	BOOL	bEnabled;





	afx_msg void OnBnClickedButtonCheck();
	afx_msg void OnBnClickedCheckCompress();
	afx_msg void OnBnClickedButtonVcode();
};

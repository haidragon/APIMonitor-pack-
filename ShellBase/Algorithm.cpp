#include "stdafx.h"
#include "Algorithm.h"



uint32_t			 crc32_table[256];	// CRC32计算表格
BOOL				 g_Crc32Table = FALSE;//是否生成了CRC32表格




//////////////////////////////////////////////////////////////////////////
//	KMP匹配算法主接口
//	参数：
//	char *		s		- 搜索的数据块指针
//	int			sLength	- 数据块大小
//	char *		p		- 匹配特征串指针
//	int			pLength	- 特征串大小
//	int *		prefix	- 前缀指针
//	若找到第一个匹配串，则立刻返回TRUE
//////////////////////////////////////////////////////////////////////////
bool kmpMatch(char * s, int sLength, char * p, int pLength, int *prefix)
{
	DWORD	dwOffset;
	int pPoint = 0;
	for (int i = 0; i <= sLength - pLength; i++)
	{


		while (pPoint != 0 && (s[i] != p[pPoint]))
		{
			pPoint = prefix[pPoint - 1];
		}
		if (s[i] == p[pPoint])
		{
			pPoint++;
			if (pPoint == pLength)
			{
				dwOffset = i - pPoint + 1;
				if ((s + dwOffset) != p)
				{
					//printf("找到正确的匹配值 Base: 0x%08X 匹配串: 0x%08X \n", dwOffset + s, p);

					return true;
				}

				//pPoint = 0;//上一个在s匹配的字符串,不能成为下一个匹配字符串的一部分  
				pPoint = prefix[pPoint - 1];//上一个在s匹配的字符串,也能成为下一个匹配字符串的一部分  
			}
		}
	}
	return FALSE;
}



//////////////////////////////////////////////////////////////////////////
//	获取前缀
//	参数：
//	char *		p		- 特征串指针
//	int			length	- 特征串长度
//	int *		prefix	- 前缀指针
//////////////////////////////////////////////////////////////////////////


void kmpPrefixFunction(char *p, int length, int *prefix)
{
	prefix[0] = 0;
	int k = 0;//前缀的长度  
	for (int i = 1; i < length; i++)
	{
		while (k > 0 && p[k] != p[i])
		{
			k = prefix[k - 1];
		}
		if (p[k] == p[i])//说明p[0...k-1]共k个都匹配了  
		{
			k = k + 1;
		}
		prefix[i] = k;
	}
}





//////////////////////////////////////////////////////////////////////////
//	生成CRC32表格，计算给定区域的CRC32值
//	参数：
//	UCHAR *				string		- 缓冲区指针
//	uint32_t			size		- 缓冲区大小
//	返回值： CRC32
//////////////////////////////////////////////////////////////////////////

DWORD	CalcuCRC(UCHAR *string, uint32_t size)
{
	//1. 生成CRC32 表格

	if (g_Crc32Table == FALSE)	MakeCRC32Table();




	//2. 计算CRC32值
	uint32_t crc = 0xFFFFFFFF;

	while (size--)
		crc = (crc >> 8) ^ (crc32_table[(crc ^ *string++) & 0xff]);


	return crc;
}




///////////////////////////////////////////////////////////////////////////
//	生成CRC32表格
//////////////////////////////////////////////////////////////////////////


VOID	MakeCRC32Table()
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

	g_Crc32Table = TRUE;

}
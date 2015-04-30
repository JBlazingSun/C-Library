#include "stdafx.h"



DWORD CRC32(BYTE* ptr,DWORD Size)
{

	DWORD crcTable[256],crcTmp1;

	//动态生成CRC-32表
	for (int i=0; i<256; i++)
	{
		crcTmp1 = i;
		for (int j=8; j>0; j--)
		{
			if (crcTmp1&1) crcTmp1 = (crcTmp1 >> 1) ^ 0xEDB88320L;
			else crcTmp1 >>= 1;
		}

		crcTable[i] = crcTmp1;
	}
	//计算CRC32值
	DWORD crcTmp2= 0xFFFFFFFF;
	while(Size--)
	{
		crcTmp2 = ((crcTmp2>>8) & 0x00FFFFFF) ^ crcTable[ (crcTmp2^(*ptr)) & 0xFF ];
		ptr++;
	}

	return (crcTmp2^0xFFFFFFFF);
}



BOOL IsFileModified()
{

	DWORD fileSize,OriginalCRC32,NumberOfBytesRW;
	WORD* pMZheader;
	WORD pPEheaderRVA;
	TCHAR  *pBuffer ,szFileName[MAX_PATH]; 



	//获得文件名
	GetModuleFileName(NULL,szFileName,MAX_PATH);
	//打开文件
	HANDLE hFile = CreateFile(
		szFileName,
		GENERIC_READ,
		FILE_SHARE_READ, 
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if ( hFile == INVALID_HANDLE_VALUE ) return FALSE;


	//获得文件长度 :
	fileSize = GetFileSize(hFile,NULL);
	if (fileSize == 0xFFFFFFFF) return FALSE;

	pBuffer = new TCHAR [fileSize];     // 申请内存,也可用VirtualAlloc等函数申请内存
	ReadFile(hFile,pBuffer, fileSize, &NumberOfBytesRW, NULL);//读取文件内容
	CloseHandle(hFile);  //关闭文件



	pMZheader=(WORD*)pBuffer; //此时pMZheader指向文件头
	pPEheaderRVA = *(WORD*)((byte*)pMZheader+0x3c);//读3ch处的PE文件头指针
	//CString ab;
	//ab.Format("%x",pPEheaderRVA);
	//MessageBox(NULL,"已修改",ab,NULL);
	//定位到PE文件头（即字串“PE\0\0”处）前4个字节处，并读出储存在这里的CRC-32值：
	OriginalCRC32 =*((DWORD *)((byte*)pMZheader+pPEheaderRVA-4));
	OriginalCRC32^=0x4597563;
	fileSize=fileSize-DWORD(pPEheaderRVA);//将PE文件头前那部分数据去除
	DWORD tmp;
	tmp=pPEheaderRVA;
	pMZheader=(WORD*)((byte*)pMZheader+tmp);//将pMZheader指向PE文件头
	//ab.Format("%x",*pMZheader);
	//比较CRC32值
	//MessageBox(NULL,"已修改",ab,NULL);

	if (CRC32((BYTE*)pMZheader,fileSize) == OriginalCRC32 )
	{
		//MessageBox(NULL,"未修改","",NULL);
		return TRUE;
	}
	else
	{
		//CString aa;
		//aa.Format("nowcrc32=%x,old=%x",CRC32((BYTE*)pMZheader,fileSize),OriginalCRC32);
		//MessageBox(NULL,"已修改",aa,NULL);
		return FALSE;
	}

}
/*
用法  

	if (!IsFileModified())
	{
		MessageBox(L"被修改",0,0);
	}
	生成后用add2crc32.exe patch
	
	*/
#include "stdafx.h"



DWORD CRC32(BYTE* ptr,DWORD Size)
{

	DWORD crcTable[256],crcTmp1;

	//��̬����CRC-32��
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
	//����CRC32ֵ
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



	//����ļ���
	GetModuleFileName(NULL,szFileName,MAX_PATH);
	//���ļ�
	HANDLE hFile = CreateFile(
		szFileName,
		GENERIC_READ,
		FILE_SHARE_READ, 
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if ( hFile == INVALID_HANDLE_VALUE ) return FALSE;


	//����ļ����� :
	fileSize = GetFileSize(hFile,NULL);
	if (fileSize == 0xFFFFFFFF) return FALSE;

	pBuffer = new TCHAR [fileSize];     // �����ڴ�,Ҳ����VirtualAlloc�Ⱥ��������ڴ�
	ReadFile(hFile,pBuffer, fileSize, &NumberOfBytesRW, NULL);//��ȡ�ļ�����
	CloseHandle(hFile);  //�ر��ļ�



	pMZheader=(WORD*)pBuffer; //��ʱpMZheaderָ���ļ�ͷ
	pPEheaderRVA = *(WORD*)((byte*)pMZheader+0x3c);//��3ch����PE�ļ�ͷָ��
	//CString ab;
	//ab.Format("%x",pPEheaderRVA);
	//MessageBox(NULL,"���޸�",ab,NULL);
	//��λ��PE�ļ�ͷ�����ִ���PE\0\0������ǰ4���ֽڴ��������������������CRC-32ֵ��
	OriginalCRC32 =*((DWORD *)((byte*)pMZheader+pPEheaderRVA-4));
	OriginalCRC32^=0x4597563;
	fileSize=fileSize-DWORD(pPEheaderRVA);//��PE�ļ�ͷǰ�ǲ�������ȥ��
	DWORD tmp;
	tmp=pPEheaderRVA;
	pMZheader=(WORD*)((byte*)pMZheader+tmp);//��pMZheaderָ��PE�ļ�ͷ
	//ab.Format("%x",*pMZheader);
	//�Ƚ�CRC32ֵ
	//MessageBox(NULL,"���޸�",ab,NULL);

	if (CRC32((BYTE*)pMZheader,fileSize) == OriginalCRC32 )
	{
		//MessageBox(NULL,"δ�޸�","",NULL);
		return TRUE;
	}
	else
	{
		//CString aa;
		//aa.Format("nowcrc32=%x,old=%x",CRC32((BYTE*)pMZheader,fileSize),OriginalCRC32);
		//MessageBox(NULL,"���޸�",aa,NULL);
		return FALSE;
	}

}
/*
�÷�  

	if (!IsFileModified())
	{
		MessageBox(L"���޸�",0,0);
	}
	���ɺ���add2crc32.exe patch
	
	*/
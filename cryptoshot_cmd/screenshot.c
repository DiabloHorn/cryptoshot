#include <Windows.h>
#include <stdio.h>
#include "polarssl\pk.h"

//set to 1 for OutputDebugString usage instead of file output
#define DISPLAY_ERRORS 0
//error level output, you know the drill
#define DBG_INFO 1
#define DBG_WARNING 2
#define DBG_ERROR 3

#define WIN32_LEAN_AND_MEAN
/*
http://stackoverflow.com/questions/3291167/how-to-make-screen-screenshot-with-win32-in-c
Use GetDC(NULL); to get a DC for the entire screen.
Use CreateCompatibleDC to get a compatible DC.
Use CreateCompatibleBitmap to create a bitmap to hold the result.
Use SelectObject to select the bitmap into the compatible DC.
Use BitBlt to copy from the screen DC to the compatible DC.
Deselect the bitmap from the compatible DC.
When you create the compatible bitmap, you want it compatible with the screen DC, not the compatible DC.

Capturing an Image
http://msdn.microsoft.com/en-us/library/windows/desktop/dd183402(v=vs.85).aspx

http://www.codeproject.com/Articles/101272/Creation-of-Multi-monitor-Screenshots-Using-WinAPI
http://www.codeproject.com/Articles/2522/Multiple-Monitor-Support#xx223852xx

https://polarssl.org/kb/compiling-and-building/using-polarssl-in-microsoft-visual-studio-2010
https://polarssl.org/discussions/generic/how-to-read-an-openssl-generated-pem-txt-file
http://stackoverflow.com/questions/1231178/load-an-x509-pem-file-into-windows-cryptoapi
smaller exe
http://thelegendofrandom.com/blog/archives/2231
*/

/*
	prints out messages either to screen or to file
	It being error messages, thus unencrypted be careful
*/
void outputerror(int dbglevel,const char *format,...){
	int outputstringsize = 1024;
	int pos = 0;
	char outputstring[1024] = {0}; //should be more then enough
	va_list args = NULL;

	va_start (args, format);
	switch(dbglevel){
		case DBG_INFO:
			pos = sprintf_s(outputstring,outputstringsize,"%s\n","::INFO::");
			break;
		case DBG_WARNING:
			pos = sprintf_s(outputstring,outputstringsize,"%s\n","::WARNING::");
			break;
		case DBG_ERROR:
			pos = sprintf_s(outputstring,outputstringsize,"%s\n","::ERROR::");
			break;
	}
	vsprintf_s((outputstring+pos),outputstringsize,format,args);
	if (pos == -1){
		sprintf_s(outputstring,outputstringsize,"%s\n%s:%s","::ERROR::","vsprintf_s failed due to format string or null pointers",format);
	}
	va_end (args);
	#ifdef DISPLAY_ERRORS
		OutputDebugString(outputstring);
	#else
		//do nothing
	#endif
}

/*
	Retrieves the public key from itself, layout on disk:
	[exe file [public key] [public key size] ]
*/
unsigned char *getpublickeyfromself(const char *filename,int *keylen){
	HANDLE openedfile = NULL;
	int filesize = 0;
	BOOL fileread = FALSE;
	unsigned char *publickey;
	int publickeysize = {0};
	DWORD bytesread;

	openedfile = CreateFile(filename,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	filesize = GetFileSize(openedfile,NULL);
	printf("fp %i\n",SetFilePointer(openedfile,-4,NULL,FILE_END));
	ReadFile(openedfile,&publickeysize,4,&bytesread,NULL);
	publickey = (unsigned char *)malloc(publickeysize+1);
	SecureZeroMemory(publickey,publickeysize+1);
	printf("fp %i\n",SetFilePointer(openedfile,(-4-publickeysize),NULL,FILE_END));
	ReadFile(openedfile,publickey,publickeysize,&bytesread,NULL);
	CloseHandle(openedfile);
	*keylen = publickeysize;
	return publickey;
}

/*
	Takes a screenshot of the screen and saves it in memory
*/
int takescreenshot(char **screenshotbuffer,int *screenshotbuffersize){
	//declaring & initializing needed vars
	HDC screendc = NULL;
	HDC compatiblescreendc = NULL;
	HBITMAP compatiblebitmap = NULL;
	HGDIOBJ selectedobject = NULL;
	BOOL bitbltresult = FALSE;
	int getobjectresult = 0;
	BITMAP finalbmp = {0};
	BITMAPFILEHEADER bmfileheader = {0};    
	BITMAPINFOHEADER bminfoheader = {0};
	DWORD dwBmpSize = 0;
	HANDLE hDIB = NULL;
	char *lpbitmap = NULL;
	int getdibitsresult = 0;	
	DWORD dwSizeofDIB = 0;
	int screenwidth = 0;
	int screenheight = 0;
	int leftxscreenpos = 0;
	int leftyscreenpos = 0;	
	char currentpath[MAX_PATH] = {0};

	//width in pixels of the virtual screen
	leftxscreenpos = GetSystemMetrics(SM_XVIRTUALSCREEN);
	//height in pixels of the virtual screen
	leftyscreenpos = GetSystemMetrics(SM_YVIRTUALSCREEN);
	//left side virtual screen coordinates
	screenwidth = GetSystemMetrics(SM_CXVIRTUALSCREEN);
	//top side virtual screen coordinates
	screenheight = GetSystemMetrics(SM_CYVIRTUALSCREEN);
	/*actually take the screenshot*/
	screendc = GetDC(NULL); 
	if(screendc == NULL){
		outputerror(DBG_ERROR,"%s","GetDC() Failed");
		return 1;
	}
	compatiblescreendc = CreateCompatibleDC(screendc);
	if(compatiblescreendc == NULL){
		outputerror(DBG_ERROR,"%s","CreateCompatibleDC() Failed");
		ReleaseDC(NULL,screendc);
		return 1;
	}
	compatiblebitmap = CreateCompatibleBitmap(screendc,screenwidth,screenheight);
	if(compatiblebitmap == NULL){
		outputerror(DBG_ERROR,"%s","CreateCompatibleBitmap() Failed");
		ReleaseDC(NULL,screendc);
		DeleteDC(compatiblescreendc);
		return 1;
	}
	selectedobject = SelectObject(compatiblescreendc,compatiblebitmap);
	if(selectedobject == NULL || selectedobject == HGDI_ERROR){
		outputerror(DBG_ERROR,"%s","SelectObject() Failed");
		ReleaseDC(NULL,screendc);
		DeleteDC(compatiblescreendc);
		DeleteObject(compatiblebitmap);
		return 1;
	}
	bitbltresult = BitBlt(compatiblescreendc,0,0,screenwidth,screenheight,screendc,leftxscreenpos,leftyscreenpos,SRCCOPY);
	if(bitbltresult == 0){
		outputerror(DBG_ERROR,"%s %d","BitBlt() Failed", GetLastError());
		ReleaseDC(NULL,screendc);
		DeleteDC(compatiblescreendc);
		DeleteObject(compatiblebitmap);		
		return 1;
	}
	/*save the screenshot to file*/
	getobjectresult = GetObject(compatiblebitmap,sizeof(BITMAP),&finalbmp);
	if(getobjectresult == 0){
		outputerror(DBG_ERROR,"%s","GetObject() Failed");
		ReleaseDC(NULL,screendc);
		DeleteDC(compatiblescreendc);
		DeleteObject(compatiblebitmap);
		return 1;
	}

	//bmp file format good read: http://en.wikipedia.org/wiki/BMP_file_format
	bminfoheader.biSize = sizeof(BITMAPINFOHEADER);    
    bminfoheader.biWidth = screenwidth;    
    bminfoheader.biHeight = screenheight;  
    bminfoheader.biPlanes = 1;    
    bminfoheader.biBitCount = 32;    
    bminfoheader.biCompression = BI_RGB;    
    bminfoheader.biSizeImage = 0;  
    bminfoheader.biXPelsPerMeter = 0;    
    bminfoheader.biYPelsPerMeter = 0;    
    bminfoheader.biClrUsed = 0;    
    bminfoheader.biClrImportant = 0;

	dwBmpSize = ((screenwidth * bminfoheader.biBitCount + 31) / 32) * 4 * screenheight;

	hDIB = GlobalAlloc(GHND,dwBmpSize); 
    lpbitmap = (char *)GlobalLock(hDIB);  
	//get the actual bitmap 'bits'
	getdibitsresult = GetDIBits(compatiblescreendc, compatiblebitmap, 0,(UINT)finalbmp.bmHeight, lpbitmap, (BITMAPINFO *)&bminfoheader, DIB_RGB_COLORS);
	if(getdibitsresult == 0){
		outputerror(DBG_ERROR,"%s","GetDIBits() Failed");
		ReleaseDC(NULL,screendc);
		DeleteDC(compatiblescreendc);
		DeleteObject(compatiblebitmap);
		SecureZeroMemory(lpbitmap,dwBmpSize);
		GlobalUnlock(hDIB); 
		return 1;
	}

    dwSizeofDIB = dwBmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bmfileheader.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER) + (DWORD)sizeof(BITMAPINFOHEADER); 
    bmfileheader.bfSize = dwSizeofDIB; 
    bmfileheader.bfType = 0x4D42;	

	outputerror(DBG_INFO,"%s\n","screenshot taken, preparing memory file");
	*screenshotbuffersize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwBmpSize;
	outputerror(DBG_INFO,"%s %i\n","memfile size",*screenshotbuffersize);
	*screenshotbuffer = (char *)malloc(*screenshotbuffersize);
	if(screenshotbuffer == NULL){
		Sleep(10000);// 10 seconds
		*screenshotbuffer = (char *)malloc(*screenshotbuffersize);
		if(screenshotbuffer == NULL){
			outputerror(DBG_ERROR,"%s","malloc() final file failed");
			ReleaseDC(NULL,screendc);
			DeleteDC(compatiblescreendc);
			DeleteObject(compatiblebitmap);
			SecureZeroMemory(lpbitmap,dwBmpSize);
			GlobalUnlock(hDIB);
			return 1;
		}
	}
	outputerror(DBG_INFO,"%s\n","memfile prepared, copy bytes");
	/* create the full file in memory */
	memcpy_s(*screenshotbuffer,*screenshotbuffersize,&bmfileheader,sizeof(BITMAPFILEHEADER));
	memcpy_s(*screenshotbuffer+sizeof(BITMAPFILEHEADER),*screenshotbuffersize,&bminfoheader,sizeof(BITMAPINFOHEADER));
	memcpy_s(*screenshotbuffer+sizeof(BITMAPFILEHEADER)+sizeof(BITMAPINFOHEADER),*screenshotbuffersize,lpbitmap,dwBmpSize);
			
	/* we could have used more of these in this app */
	SecureZeroMemory(lpbitmap,dwBmpSize);
	SecureZeroMemory(&bmfileheader,sizeof(BITMAPFILEHEADER));
	SecureZeroMemory(&bminfoheader,sizeof(BITMAPINFOHEADER));
	/*release resources*/
	GlobalUnlock(hDIB);
	ReleaseDC(NULL,screendc);
	DeleteDC(compatiblescreendc);
	DeleteObject(compatiblebitmap);
	GlobalFree(hDIB);
	return 0;
}

void rsacrypt(const unsigned char *rsapublickey, int rsapublickeylen){
	pk_context pkctx;
	int pkresult = 0;
	unsigned char *output = NULL;
	size_t olen=0,osize = 0;

	pk_init(&pkctx);
	pkresult = pk_parse_public_key(&pkctx,rsapublickey,rsapublickeylen);
	printf("pkloadkey %i\n",pkresult);
	pkresult = 0;
	pkresult = pk_can_do(&pkctx,POLARSSL_PK_RSA);
	printf("pkcando %i\n",pkresult);
	printf("%s %Iu\n",pkctx.pk_info->name,pk_get_len(&pkctx));
	output = (unsigned char *)malloc(pk_get_len(&pkctx));
	free(output);
	pk_free(&pkctx);
}




int main(int argc, char *argv[]){
	char *finalbmpfile = NULL;
	int finalbmpfilesize = 0;
	DWORD dwBytesWritten = 0;
	HANDLE hFile = NULL;

	/*temp
	unsigned char *pubrsakey;
	int pubkeylen = 0;
	GetModuleFileName(NULL,&currentpath[0],sizeof(currentpath));
	printf("%s\n",currentpath);
	pubrsakey = getpublickeyfromself(&currentpath[0],&pubkeylen);
	printf("len: %i\n %s\n",pubkeylen,pubrsakey);
	rsacrypt(pubrsakey,pubkeylen);
	exit(0);
	temp*/


	if(takescreenshot(&finalbmpfile,&finalbmpfilesize) == 1){
		SecureZeroMemory(finalbmpfile,finalbmpfilesize);
		free(finalbmpfile);
		exit(1);
	}

	hFile = CreateFile("screen.bmp", GENERIC_WRITE, 0, NULL,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile,finalbmpfile,finalbmpfilesize,&dwBytesWritten,NULL);
	CloseHandle(hFile);
	SecureZeroMemory(finalbmpfile,finalbmpfilesize);
	free(finalbmpfile);
	return 0;
}
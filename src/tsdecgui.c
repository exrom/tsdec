/********************************************************************************

TSDEC   

Offline decrypter for recorded DVB transport streams (TS) 
using a control word log file (CWL).      by ganymede

This program is free software; you can redistribute it and/or modify it under 
the terms of the GNU General Public License as published by the Free Software 
Foundation; either Version 3 of the License, or (at your option) any later Version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY 
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with 
this program; if not, see <http://www.gnu.org/licenses/>.

********************************************************************************/

#define STRICT

#include <windows.h>
#include <commctrl.h>
#include <string.h>
#include <process.h>
#include <stdio.h>

#ifndef _WINDOWS
#error  _WINDOWS must be defined for GUI version!
#endif

#include "tsdec.h"

/* some GUI positions */
#define MAINWIDTH       400
#define MAINHEIGHT      350
#define V1              25    /* 1st file input */
#define V2              65    /* 2nd file input */
#define V3              95
#define VSTAT           185
#define BRDR            7

#define MS_Idle         0
#define MS_Decrypting   1

#define VERBOSELEVEL    2

/* declarations */
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

/* globals */
static HWND          hWnd;
static MSG           msg;
static WNDCLASS      wc;
static OPENFILENAME  ofn;

static HWND          hEditStatus;

char     szInFile[260];
char     szCWLFile[260];
char     szOutFile[260];
const char szAppName[]        = "TSDEC  The offline decrypter V0.4.1";
const char szClassName[]      = "TSDEC";
const char  szTSIN[]          = "encrypted transport stream file";
const char  szCWL[]           = "control word log file";
const char  szStatus[]        = "Messages";
const char *szExt             = ".ts";
const char *szNewExt          = "_decrypted.ts";
const char *szDecrypt         = "Decrypt!";
LPDWORD     lpDecryptThreadId=0;
unsigned char ThreadRunning=0;
unsigned char decryptCWLRetVal;

/* functions */

int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    PSTR szCmdLine, int iCmdShow)
{

   wc.style         =  CS_HREDRAW | CS_VREDRAW;
   wc.lpfnWndProc   =  WndProc;
   wc.cbClsExtra    =  0;
   wc.cbWndExtra    =  0;
   wc.hInstance     =  hInstance;
   wc.hCursor       =  NULL;
	wc.hIcon			  =  LoadIcon(hInstance, MAKEINTRESOURCE(101));
   wc.hbrBackground =  (HBRUSH)(COLOR_BTNFACE+1);
   wc.lpszClassName =  szClassName;
   wc.lpszMenuName  =  NULL;

   RegisterClass(&wc);

   hWnd = CreateWindow(szClassName,szAppName,WS_OVERLAPPED| WS_SYSMENU | WS_MINIMIZEBOX,300,300,MAINWIDTH,MAINHEIGHT,NULL,NULL,hInstance,NULL);

   ShowWindow(hWnd, iCmdShow);
   UpdateWindow(hWnd);

   while (GetMessage(&msg, NULL, 0, 0))
   {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
   }

   return msg.wParam;
}


unsigned __stdcall DecryptionThreadMain(void *pArgs)
{
   decryptCWLRetVal = decryptCWL();
   ThreadRunning = 0;
   return 0;
}

void CloseAllFiles(void)
{
   unload_cws();
   close_input_file();
   close_output_file();
}

void WinMsgDbg(unsigned char *buf) 
{
   SendMessage(hEditStatus, EM_SETSEL,       GetWindowTextLength(hEditStatus), GetWindowTextLength(hEditStatus));
   SendMessage(hEditStatus, EM_REPLACESEL,   0, (LPARAM)buf);
   SendMessage(hEditStatus, EM_SCROLLCARET,  0, 0);
}


LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
   PAINTSTRUCT ps;
   HDC         hDC;

   const UINT GUIRefresh = 1;
   static unsigned char u8Decrypting=0;
   static HWND hOpenTSButton;
   static HWND hOpenCWLButton;
   static HWND hRUNSTOPButton;
   static HWND hEditTS;
   static HWND hEditCWL;
   static HWND hCBPlayTS;
   static HWND hProgress;

   switch (message)
   {
   case WM_CREATE:
      hEditTS        = CreateWindowEx( WS_EX_CLIENTEDGE|WS_TABSTOP, "edit" ,szInFile,  WS_TABSTOP | WS_CHILD | WS_VISIBLE,           BRDR, V1, MAINWIDTH-BRDR-40, 20,hWnd,NULL,((LPCREATESTRUCT) lParam) -> hInstance,NULL);
      SendMessage(hEditTS,WM_SETFONT,(int)GetStockObject(ANSI_VAR_FONT),0);
      hOpenTSButton  = CreateWindow(  "button","...",   WS_CHILD | WS_VISIBLE|WS_TABSTOP,                        MAINWIDTH-BRDR-30, V1, 20, 20,hWnd,NULL,((LPCREATESTRUCT) lParam) -> hInstance,NULL);
      SendMessage(hOpenTSButton,WM_SETFONT,(int)GetStockObject(ANSI_VAR_FONT),0);
      /*SetWindowText(hEditTS, "d:\\PROJ\\TSDEC_GUI\\H2TD.ts");*/

      hEditCWL       = CreateWindowEx( WS_EX_CLIENTEDGE, "edit" ,"",  WS_TABSTOP | WS_CHILD | WS_VISIBLE,           BRDR, V2, MAINWIDTH-BRDR-40, 20,hWnd,NULL,((LPCREATESTRUCT) lParam) -> hInstance,NULL);
      SendMessage(hEditCWL,WM_SETFONT,(int)GetStockObject(ANSI_VAR_FONT),0);
      hOpenCWLButton = CreateWindow(  "button","...",   WS_CHILD | WS_VISIBLE|WS_TABSTOP,                        MAINWIDTH-BRDR-30, V2, 20, 20,hWnd,NULL,((LPCREATESTRUCT) lParam) -> hInstance,NULL);
      SendMessage(hOpenCWLButton,WM_SETFONT,(int)GetStockObject(ANSI_VAR_FONT),0);
      /*SetWindowText(hEditCWL, "d:\\PROJ\\TSDEC_GUI\\all.cwl");*/

      hRUNSTOPButton   = CreateWindow(  "button",szDecrypt,     WS_TABSTOP | WS_CHILD | WS_VISIBLE,  MAINWIDTH-69, V3, 52, 40,hWnd,NULL,((LPCREATESTRUCT) lParam) -> hInstance,NULL);
      EnableWindow(hRUNSTOPButton, 0);
      SendMessage(hRUNSTOPButton,WM_SETFONT,(int)GetStockObject(ANSI_VAR_FONT),0);

      hProgress = CreateWindow(PROGRESS_CLASS,NULL,WS_CHILD | WS_VISIBLE|WS_TABSTOP,7,VSTAT-40,MAINWIDTH-20,15,hWnd,NULL,((LPCREATESTRUCT) lParam) -> hInstance,NULL);

      hCBPlayTS = CreateWindow("button", "play TS file after decryption",   WS_TABSTOP | BS_AUTOCHECKBOX |WS_CHILD | WS_VISIBLE, BRDR, V3, 157, 20,hWnd,NULL,((LPCREATESTRUCT) lParam) -> hInstance,NULL);
      SendMessage(hCBPlayTS,WM_SETFONT,(int)GetStockObject(ANSI_VAR_FONT),0);

      hEditStatus   = CreateWindowEx( WS_EX_CLIENTEDGE , "edit" ,"",  WS_TABSTOP |ES_MULTILINE|ES_READONLY| WS_CHILD | WS_VISIBLE | WS_VSCROLL /*ES_AUTOVSCROLL*/,  BRDR, VSTAT, MAINWIDTH-2*BRDR-5, MAINHEIGHT-VSTAT-BRDR-27,hWnd,NULL,((LPCREATESTRUCT) lParam) -> hInstance,NULL);
      SendMessage(hEditStatus,WM_SETFONT,(int)GetStockObject(ANSI_VAR_FONT),0);
      SendMessage(hEditStatus,EM_LIMITTEXT,0xFFFFF,0);   /* allocate 1MB text buffer insted of 32KB. If more debug messages come up, the latest text is truncated */

      return 0;
   case WM_TIMER:
      {
         if (ThreadRunning) 
         {
            SendMessage(hProgress, PBM_SETPOS, (gNumberOfPackets>0xffffff?(gCurrentPacket>>16):(  (gNumberOfPackets>0xffff)?(gCurrentPacket>>8):gCurrentPacket) ),0);
            /*InvalidateRect(hWnd, NULL, TRUE);*/
         }
         else
         {
            /* done */
            KillTimer(hWnd, GUIRefresh);
            CloseAllFiles();
            SendMessage(hProgress, PBM_SETPOS, 0, 0);
            SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
            SetWindowText(hRUNSTOPButton, szDecrypt);
            u8Decrypting=0;
            InvalidateRect(hWnd, NULL, TRUE);
            if (  (BST_CHECKED==SendMessage(hCBPlayTS,BM_GETCHECK,0,0)) &&
                  ( (decryptCWLRetVal==RET_OK) || (decryptCWLRetVal==RET_OUTOFCWS) || (decryptCWLRetVal==RET_NOTCRYPTED) )
               )

               ShellExecute(NULL,NULL,szOutFile,NULL,NULL,SW_SHOWNORMAL);
         }
      }
   case WM_PAINT:
      {
         hDC = BeginPaint(hWnd, &ps);
         {
            SelectObject(hDC, GetStockObject(ANSI_VAR_FONT));
            SetBkMode(hDC, TRANSPARENT);
            TextOut(hDC, 10, V1-16, szTSIN, sizeof(szTSIN) - 1);
            TextOut(hDC, 10, V2-16, szCWL, sizeof(szCWL) - 1);
            TextOut(hDC, 10, VSTAT-17, szStatus, sizeof(szStatus) - 1);
         }
         EndPaint(hWnd, &ps);
         return 0;
      }
   case WM_COMMAND:
      {
         if (u8Decrypting == 0)
         {
            /* idle */
            if (lParam == (LPARAM)hOpenTSButton)
            {
               if (HIWORD(wParam) == BN_CLICKED)
               {
                  ofn.lStructSize   = sizeof (OPENFILENAME);
                  /*ofn.hWndOwner     = hWnd;*/
                  ofn.hwndOwner     = hWnd;
                  ofn.lpstrFilter   = "All *.*\0*.*\0Transport stream files(*.ts)\0*.ts\0";
                  ofn.nFilterIndex  = 2;
                  ofn.lpstrFile     = szInFile;
                  ofn.nMaxFile      = sizeof(szInFile);
                  ofn.Flags         = OFN_FILEMUSTEXIST|OFN_HIDEREADONLY;
                  if (GetOpenFileName(&ofn)) SetWindowText(hEditTS, szInFile);
               }
            }
            if (lParam == (LPARAM)hOpenCWLButton)
            {
               if (HIWORD(wParam) == BN_CLICKED)
               {
                  ofn.lStructSize   = sizeof (OPENFILENAME);
                  ofn.hwndOwner     = hWnd;
                  ofn.lpstrFilter   = "All *.*\0*.*\0Control word log files (*.cwl)\0*.cwl\0";
                  ofn.nFilterIndex  = 2;
                  ofn.lpstrFile     = szCWLFile;
                  ofn.nMaxFile      = sizeof(szCWLFile);
                  ofn.Flags         = OFN_FILEMUSTEXIST|OFN_HIDEREADONLY;
                  if (GetOpenFileName(&ofn)) SetWindowText(hEditCWL, szCWLFile);
               }
            }

            EnableWindow(hRUNSTOPButton, GetWindowText(hEditCWL, szCWLFile, sizeof(szCWLFile)) && GetWindowText(hEditTS, szInFile, sizeof(szInFile)));

            if (lParam == (LPARAM)hRUNSTOPButton)
            {
               SetWindowText(hEditStatus, NULL);
               /* load cwl */
               GetWindowText(hEditCWL, szCWLFile, sizeof(szCWLFile));
               if (load_cws(szCWLFile))
               {
                  CloseAllFiles();
                  MessageBox(hWnd, "Error loading cws from cwl file", "Error",0);
                  break;   /* finish case WM_COMMAND: */
               }
               /* open TS input file */
               GetWindowText(hEditTS, szInFile, sizeof(szInFile));
               if(open_input_file(szInFile))
               {
                  CloseAllFiles();
                  MessageBox(hWnd, "Error loading TS input file", "Error",0);
                  break;   /* finish case WM_COMMAND: */
               }

               /* open TS output file */
               GetWindowText(hEditTS, szOutFile, sizeof(szOutFile));
               if ( !strcmp(szOutFile+strlen(szOutFile)-strlen(szExt), szExt ) )
               {
                  *(szOutFile+strlen(szOutFile)-strlen(szExt)) = 0; /* cut off ".ts" extension */
               }
               if ( sizeof(szOutFile) > ( strlen(szOutFile) + strlen(szNewExt) ) ) 
               {
                  strncat(szOutFile,szNewExt,sizeof(szOutFile)-1);
                  szOutFile[sizeof(szOutFile)-1]='\0';
               }
               else
               {
                  CloseAllFiles();
                  MessageBox(hWnd, "Path too long for output file", "Error",0);
                  break;   /* finish case WM_COMMAND: */
               }

               if(open_output_file(szOutFile))
               {
                  CloseAllFiles();
                  MessageBox(hWnd, "Error opening TS output file", "Error",0);
                  break;   /* finish case WM_COMMAND: */
               }
               else
               {
                  /* all input files are ok, now start decryption */
                  SetTimer(hWnd, GUIRefresh, 200, NULL);
                  SetWindowText(hRUNSTOPButton, "STOP");
                  SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
                  /* max value shift 8@11.7MB and 16@2.937GB file size */
                  SendMessage(hProgress, PBM_SETRANGE, 0, MAKELPARAM (0, (gNumberOfPackets>0xffffff?(gNumberOfPackets>>16):(  (gNumberOfPackets>0xffff)?(gNumberOfPackets>>8):gNumberOfPackets) ) ) );
                  u8Decrypting=1;
                  /* start decrypting thread */
                  CreateThread(NULL,
                     0,
                     DecryptionThreadMain,
                     NULL,
                     0,
                     lpDecryptThreadId);
                  ThreadRunning=1;
                  break;
               }
            }  /* if (lParam == (LPARAM)hRUNSTOPButton) */
            break;
         }
         else   /* if (u8Decrypting == 0) */
         {
            /* decrypting */
            if (lParam == (LPARAM)hRUNSTOPButton)
            {
               u8CancelDecryption=1;   /* tell decryption thread to terminate itself */
               u8Decrypting=0;
               SendMessage(hProgress, PBM_SETPOS, 0, 0);
               /*KillTimer(hWnd, GUIRefresh);*/
               SetWindowText(hRUNSTOPButton, szDecrypt);
               break;   /* finish case WM_COMMAND: */
            }
         }
      }
      return 0;
   case WM_CLOSE:
      {
         if (u8Decrypting == 1)
         {
            if (IDOK==MessageBox(hWnd,"Decryption running!\nClose TSDEC?","Warning", MB_OKCANCEL|MB_ICONQUESTION))
            {
               DestroyWindow(hWnd);
               CloseAllFiles();
            }
         }
         else 
         {
            DestroyWindow(hWnd);
         }

         return 0;
      }
   case WM_DESTROY:
      {
         PostQuitMessage(0);
         return 0;
      }
   }
   return DefWindowProc(hWnd, message, wParam, lParam);
}

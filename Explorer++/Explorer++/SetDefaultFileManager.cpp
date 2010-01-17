/******************************************************************
 *
 * Project: Explorer++
 * File: SetDefaultFileManager.cpp
 * License: GPL - See COPYING in the top level directory
 *
 * Sets Explorer++ as the default file manager.
 *
 * Written by David Erceg
 * www.explorerplusplus.com
 *
 *****************************************************************/

/*
Notes:

- To replace Explorer for filesystem folders only,
  add a key at:
  HKEY_CLASSES_ROOT\Directory

- To replace Explorer for all folders, add a key at:
  HKEY_CLASSES_ROOT\Shell

The value of the "command" sub-key will be of the form:
  "C:\Explorer++.exe" "%1"
  where "%1" is the path passed from the shell,
  encapsulated within quotes.
*/

#include "stdafx.h"
#include "Explorer++.h"


#define KEY_DIRECTORY_SHELL		_T("Directory\\shell")
#define KEY_DIRECTORY_APP		_T("Directory\\shell\\openinexplorer++")
#define SHELL_DEFAULT_VALUE		_T("none")
#define INTERNAL_COMMAND_NAME	_T("openinexplorer++")
#define EXTERNAL_MENU_TEXT		_T("Open In Explorer++")

BOOL SetAsDefaultFileManager(void)
{
	HKEY						hKeyShell;
	HKEY						hKeyApp;
	HKEY						hKeyCommand;
	list<Filter_t>::iterator	itr;
	TCHAR						szCommand[512];
	TCHAR						szExecutable[MAX_PATH];
	DWORD						Disposition;
	LONG						ReturnValue;
	BOOL						bSuccess = FALSE;

	ReturnValue = RegOpenKeyEx(HKEY_CLASSES_ROOT,
		KEY_DIRECTORY_SHELL,0,KEY_WRITE,&hKeyShell);

	if(ReturnValue == ERROR_SUCCESS)
	{
		ReturnValue = RegCreateKeyEx(hKeyShell,INTERNAL_COMMAND_NAME,
			0,NULL,REG_OPTION_NON_VOLATILE,KEY_WRITE,
			NULL,&hKeyApp,&Disposition);

		if(ReturnValue == ERROR_SUCCESS)
		{
			/* Now, set the defaault value for the key. This
			default value will be the text that is shown on the
			context menu for folders. */
			RegSetValueEx(hKeyApp,NULL,0,REG_SZ,(LPBYTE)EXTERNAL_MENU_TEXT,
				(lstrlen(EXTERNAL_MENU_TEXT) + 1) * sizeof(TCHAR));

			/* Now, create the "command" sub-key. */
			ReturnValue = RegCreateKeyEx(hKeyApp,_T("command"),
				0,NULL,REG_OPTION_NON_VOLATILE,KEY_WRITE,
				NULL,&hKeyCommand,&Disposition);

			if(ReturnValue == ERROR_SUCCESS)
			{
				/* Get the current location of the program, and use
				it as part of the command. */
				GetCurrentProcessImageName(szExecutable,
					SIZEOF_ARRAY(szExecutable));

				StringCchPrintf(szCommand,SIZEOF_ARRAY(szCommand),
					_T("\"%s\" \"%%1\""),szExecutable);

				/* ...and write the command out. */
				ReturnValue = RegSetValueEx(hKeyCommand,NULL,0,REG_SZ,(LPBYTE)szCommand,
					(lstrlen(szCommand) + 1) * sizeof(TCHAR));

				if(ReturnValue == ERROR_SUCCESS)
				{
					/* Set the current entry as the default. */
					ReturnValue = RegSetValueEx(hKeyShell,NULL,0,REG_SZ,
						(LPBYTE)INTERNAL_COMMAND_NAME,
						(lstrlen(INTERNAL_COMMAND_NAME) + 1) * sizeof(TCHAR));

					if(ReturnValue == ERROR_SUCCESS)
					{
						bSuccess = TRUE;
					}
				}

				RegCloseKey(hKeyCommand);
			}

			RegCloseKey(hKeyApp);
		}

		RegCloseKey(hKeyShell);
	}

	return bSuccess;
}

BOOL RemoveAsDefaultFileManager(void)
{
	HKEY						hKeyShell;
	list<Filter_t>::iterator	itr;
	LONG						ReturnValue1 = 1;
	LSTATUS						ReturnValue2 = 1;

	/* Remove the shell default value. */
	ReturnValue1 = RegOpenKeyEx(HKEY_CLASSES_ROOT,
		KEY_DIRECTORY_SHELL,0,KEY_WRITE,&hKeyShell);

	if(ReturnValue1 == ERROR_SUCCESS)
	{
		ReturnValue1 = RegSetValueEx(hKeyShell,NULL,0,REG_SZ,
			(LPBYTE)SHELL_DEFAULT_VALUE,
			(lstrlen(SHELL_DEFAULT_VALUE) + 1) * sizeof(TCHAR));

		if(ReturnValue1 == ERROR_SUCCESS)
		{
			/* Remove the main command key. */
			ReturnValue2 = SHDeleteKey(HKEY_CLASSES_ROOT,KEY_DIRECTORY_APP);
		}

		RegCloseKey(hKeyShell);
	}

	return ((ReturnValue1 == ERROR_SUCCESS) && (ReturnValue2 == ERROR_SUCCESS));
}
/******************************************************************
 *
 * Project: ShellBrowser
 * File: iDropTarget.cpp
 * License: GPL - See COPYING in the top level directory
 *
 * Handles the dropping of items onto
 * the main listview.
 *
 * Written by David Erceg
 * www.explorerplusplus.com
 *
 *****************************************************************/

#include "stdafx.h"
#include "IShellView.h"
#include "iShellBrowser_internal.h"
#include "../Helper/Helper.h"
#include "../Helper/Buffer.h"
#include "../Helper/FileOperations.h"


/* Scroll definitions. */
#define MIN_X_POS	20
#define MIN_Y_POS	20
#define X_SCROLL_AMOUNT	10
#define Y_SCROLL_AMOUNT	10

HRESULT _stdcall CFolderView::DragEnter(IDataObject *pDataObject,
DWORD grfKeyState,POINTL ptl,DWORD *pdwEffect)
{
	FORMATETC	ftc = {CF_HDROP,0,DVASPECT_CONTENT,-1,TYMED_HGLOBAL};
	HRESULT		hr;
	HRESULT		hReturn;
	POINT pt;

	m_bPerformingDrag = TRUE;
	m_bDeselectDropFolder = FALSE;
	m_iDropFolder = -1;

	if(m_bVirtualFolder && !m_bDragging)
	{
		m_bDataAccept	= FALSE;
		*pdwEffect		= DROPEFFECT_NONE;

		hReturn = S_OK;
	}
	else
	{
		/* Check whether the drop source has the type of data (CF_HDROP)
		that is needed for this drag operation. */
		hr = pDataObject->QueryGetData(&ftc);

		/* DON'T use SUCCEEDED (QueryGetData() will return S_FALSE on
		failure). */
		if(hr == S_OK)
		{
			m_bDataAccept = TRUE;

			m_bOnSameDrive = CheckItemLocations(pDataObject,0);
			*pdwEffect = DetermineCurrentDragEffect(grfKeyState,*pdwEffect,
				m_bDataAccept,m_bOnSameDrive);
		}
		else
		{
			m_bDataAccept	= FALSE;
			*pdwEffect		= DROPEFFECT_NONE;
		}

		hReturn = S_OK;
	}

	if(grfKeyState & MK_LBUTTON)
		m_DragType = DRAG_TYPE_LEFTCLICK;
	else if(grfKeyState & MK_RBUTTON)
		m_DragType = DRAG_TYPE_RIGHTCLICK;

	pt.x = ptl.x;
	pt.y = ptl.y;

	/* Notify the drop target helper that an object has been dragged into
	the window. */
	m_pDropTargetHelper->DragEnter(m_hListView,pDataObject,&pt,*pdwEffect);

	return hReturn;
}

HRESULT _stdcall CFolderView::DragOver(DWORD grfKeyState,POINTL ptl,DWORD *pdwEffect)
{
	RECT	rc;
	POINT	pt;

	*pdwEffect = DetermineCurrentDragEffect(grfKeyState,*pdwEffect,
		m_bDataAccept,m_bOnSameDrive);

	pt.x = ptl.x;
	pt.y = ptl.y;

	/* Notify the drop helper of the current operation. */
	m_pDropTargetHelper->DragOver((LPPOINT)&pt,*pdwEffect);

	ScreenToClient(m_hListView,(LPPOINT)&pt);
	GetClientRect(m_hListView,&rc);

	/* If the cursor is too close to either the top or bottom
	of the listview, scroll the listview in the required direction. */
	ScrollListViewFromCursor(m_hListView,&pt);

	HandleDragSelection((LPPOINT)&pt);

	if(m_bDataAccept)
	{
		if(!m_bOverFolder)
			ListView_HandleInsertionMark(m_hListView,0,&pt);
		else
			ListView_HandleInsertionMark(m_hListView,0,NULL);
	}

	return S_OK;
}

/* Determines the drop effect based on the
location of the source and destination
directories.
Note that the first dropped file is taken
as representative of the rest (meaning that
if the files come from different drives,
whether this operation is classed as a copy
or move is only based on the location of the
first file). */
DWORD CFolderView::CheckItemLocations(IDataObject *pDataObject,int iDroppedItem)
{
	FORMATETC	ftc;
	STGMEDIUM	stg;
	DROPFILES	*pdf = NULL;
	TCHAR		szFullFileName[MAX_PATH];
	TCHAR		szDestDirectory[MAX_PATH];
	HRESULT		hr;
	BOOL		bOnSameDrive = FALSE;
	int			nDroppedFiles;

	ftc.cfFormat	= CF_HDROP;
	ftc.ptd			= NULL;
	ftc.dwAspect	= DVASPECT_CONTENT;
	ftc.lindex		= -1;
	ftc.tymed		= TYMED_HGLOBAL;

	hr = pDataObject->GetData(&ftc,&stg);

	if(hr == S_OK)
	{
		pdf = (DROPFILES *)GlobalLock(stg.hGlobal);

		if(pdf != NULL)
		{
			/* Request a count of the number of files that have been dropped. */
			nDroppedFiles = DragQueryFile((HDROP)pdf,0xFFFFFFFF,NULL,NULL);

			if(iDroppedItem < nDroppedFiles)
			{
				/* Determine the name of the first dropped file. */
				DragQueryFile((HDROP)pdf,iDroppedItem,szFullFileName,
					SIZEOF_ARRAY(szFullFileName));

				/* TODO: Compare against sub-folders? (i.e. path may
				need to be adjusted if the dragged item is currently
				over a folder). */
				QueryCurrentDirectory(SIZEOF_ARRAY(szDestDirectory),
					szDestDirectory);

				if(PathIsSameRoot(szDestDirectory,szFullFileName))
					bOnSameDrive = TRUE;
				else
					bOnSameDrive = FALSE;
			}

			GlobalUnlock(stg.hGlobal);
		}
	}

	return bOnSameDrive;
}

/*
Cases:
- The dragged item is NOT over an item in the listview.
Any previously selected item should revert to its
previous state (i.e. selected if it was previously
selected; not selected if it wasn't).
- The dragged item IS over an item in the listview.
Three sub-cases:
(a) The item its over is a file (or somewhere where
the dragged file can't be dropped). Do not alter
the selection of the file in the listview.
(b) The item is over a folder. In this case, save
the items previous selection state, and select
it.
(c) The item is over itself. Do not alter selection
in any way.

Deselction occurs when:
1. The dragged file is dropped.
2. The dragged file moves over the background of the
listview, or over a file it cannot be dragged into.
3. The dragged file moves over an item it can be
dragged into (and this item is different from the
previous item that was selected).
4. The drag and drop operation is canceled.

Therefore, the ONLY time selection is maintained is when
the dragged item remains over the same selected item.

These are handled by:
1. Drop()
2. DragOver()
3. DragOver()
4. DragLeave()
*/
void CFolderView::HandleDragSelection(POINT *ppt)
{
	LVHITTESTINFO	info;
	BOOL			bClash = FALSE;
	BOOL			bOverFolder = FALSE;
	BOOL			bOverItem = FALSE;
	int				iItem;
	int				iInternalIndex = -1;

	info.pt = *ppt;
	ListView_HitTest(m_hListView,&info);

	if(!(info.flags & LVHT_NOWHERE) && info.iItem != -1)
	{
		LVITEM lvItem;

		lvItem.mask		= LVIF_PARAM;
		lvItem.iItem	= info.iItem;
		lvItem.iSubItem	= 0;
		ListView_GetItem(m_hListView,&lvItem);

		iInternalIndex = (int)lvItem.lParam;

		if(iInternalIndex != -1)
		{
			bOverItem = TRUE;

			if(m_bOverFolder && info.iItem == m_iDropFolder)
			{
				bOverFolder = TRUE;
			}
		}
	}

	if(!bOverFolder)
	{
		/* The dragged item is not over the previously
		selected item. Revert the selection state on
		the old item. */
		if(m_bOverFolder)
		{
			/* Only deselect the previous item if it
			was originally deselcted. */
			if(m_bDeselectDropFolder)
			{
				ListView_SetItemState(m_hListView,
					m_iDropFolder,0,LVIS_SELECTED);
			}
		}

		m_bOverFolder = FALSE;

		/* Now, if the dragged item is over an item in
		the listview, test it to see whether or not it
		is a folder. */
		if(bOverItem)
		{
			/* Check for a clash (only if over a folder). */
			if((m_pwfdFiles[iInternalIndex].dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				== FILE_ATTRIBUTE_DIRECTORY)
			{
				if(m_bDragging)
				{
					list<DraggedFile_t>::iterator itr;

					for(itr = m_DraggedFilesList.begin();itr != m_DraggedFilesList.end();itr++)
					{
						iItem = LocateFileItemIndex(itr->szFileName);

						if(info.iItem == iItem)
							bClash = TRUE;
					}
				}

				/* The dragged item is over a valid folder
				(that isn't itself). */
				if(!bClash)
				{
					UINT mask;

					/* Get the original selection state of the item. */
					mask = ListView_GetItemState(m_hListView,info.iItem,LVIS_SELECTED);

					if((mask & LVIS_SELECTED) == LVIS_SELECTED)
						m_bDeselectDropFolder = FALSE;
					else
						m_bDeselectDropFolder = TRUE;

					/* Select the item. */
					ListView_SetItemState(m_hListView,info.iItem,
						LVIS_SELECTED,LVIS_SELECTED);

					m_iDropFolder = info.iItem;
					m_bOverFolder = TRUE;
				}
			}
		}
	}
}

HRESULT _stdcall CFolderView::DragLeave(void)
{
	m_pDropTargetHelper->DragLeave();

	ListView_HandleInsertionMark(m_hListView,0,NULL);

	if(m_bDeselectDropFolder)
	{
		/* Deselect any folder that may have been selected during dragging. */
		ListView_SetItemState(m_hListView,m_iDropFolder,0,LVIS_SELECTED);
	}

	m_bPerformingDrag = FALSE;

	return S_OK;
}

/*
Causes any dragged files to be dropped in the current
directory.

- If the files are been dragged locally, they will simply
be moved.
- If the files are been dragged from another directory,
they will be copied/moved to the current directory.

Modifier keys (from http://blogs.msdn.com/oldnewthing/archive/2004/11/12/256472.aspx):
If Ctrl+Shift (or Alt) are held down, then the operation creates a shortcut. 
If Shift is held down, then the operation is a move. 
If Ctrl is held down, then the operation is a copy. 
If no modifiers are held down and the source and destination are on the same drive, then the operation is a move. 
If no modifiers are held down and the source and destination are on different drives, then the operation is a copy.
*/
HRESULT _stdcall CFolderView::Drop(IDataObject *pDataObject,
DWORD grfKeyState,POINTL ptl,DWORD *pdwEffect)
{
	FORMATETC		ftc;
	STGMEDIUM		stg;
	DROPFILES		*pdf = NULL;
	POINT			pt;
	TCHAR			szDestDirectory[MAX_PATH + 1];
	HRESULT			hr;
	DWORD			dwEffect;
	int				nDroppedFiles;

	pt.x = ptl.x;
	pt.y = ptl.y;

	QueryCurrentDirectory(SIZEOF_ARRAY(szDestDirectory),
		szDestDirectory);

	/* If the item(s) have been dropped over a folder in the
	listview, append the folders name onto the destination path. */
	if(m_bOverFolder)
	{
		LVITEM lvItem;

		lvItem.mask		= LVIF_PARAM;
		lvItem.iItem	= m_iDropFolder;
		lvItem.iSubItem	= 0;
		ListView_GetItem(m_hListView,&lvItem);

		PathAppend(szDestDirectory,m_pwfdFiles[(int)lvItem.lParam].cFileName);
	}

	szDestDirectory[lstrlen(szDestDirectory) + 1] = '\0';

	ftc.cfFormat	= CF_HDROP;
	ftc.ptd			= NULL;
	ftc.dwAspect	= DVASPECT_CONTENT;
	ftc.lindex		= -1;
	ftc.tymed		= TYMED_HGLOBAL;

	/* Does the dropped object contain the type of
	data we need? */
	hr = pDataObject->GetData(&ftc,&stg);

	if(hr == S_OK)
	{
		/* Need to remove the drag image before any files are copied/moved.
		This is because a copy/replace dialog may need to shown (if there
		is a collision), and the drag image no longer needs to be there.
		The insertion mark may stay until the end. */
		m_pDropTargetHelper->Drop(pDataObject,(POINT *)&pt,*pdwEffect);

		if(m_DragType == DRAG_TYPE_RIGHTCLICK)
		{
			IShellFolder *pDesktop = NULL;
			IShellFolder *pShellFolder = NULL;
			IDropTarget *pDrop = NULL;
			LPITEMIDLIST pidlDirectory = NULL;
			DWORD dwe;

			hr = GetIdlFromParsingName(szDestDirectory,&pidlDirectory);

			if(SUCCEEDED(hr))
			{
				hr = SHGetDesktopFolder(&pDesktop);

				if(SUCCEEDED(hr))
				{
					hr = pDesktop->BindToObject(pidlDirectory,0,IID_IShellFolder,(void **)&pShellFolder);

					if(SUCCEEDED(hr))
					{
						dwe = *pdwEffect;

						hr = pShellFolder->CreateViewObject(m_hListView,IID_IDropTarget,(void **)&pDrop);

						if(SUCCEEDED(hr))
						{
							pDrop->DragEnter(pDataObject,MK_RBUTTON,ptl,&dwe);

							dwe = *pdwEffect;
							pDrop->Drop(pDataObject,grfKeyState,ptl,&dwe);

							pDrop->DragLeave();

							pDrop->Release();
						}

						pShellFolder->Release();
					}

					pDesktop->Release();
				}

				CoTaskMemFree(pidlDirectory);
			}
		}
		else
		{
			pdf = (DROPFILES *)GlobalLock(stg.hGlobal);

			if(pdf != NULL)
			{
				/* Request a count of the number of files that have been dropped. */
				nDroppedFiles = DragQueryFile((HDROP)pdf,0xFFFFFFFF,NULL,NULL);

				/* If a folder was dragged locally, and it is not over a folder,
				reposition it. */
				if(m_bDragging && !m_bOverFolder)
				{
					/* The drop effect will be the same for all files
					that are been dragged locally. */
					dwEffect = DetermineCurrentDragEffect(grfKeyState,*pdwEffect,
						m_bDataAccept,m_bOnSameDrive);

					if(dwEffect == DROPEFFECT_MOVE)
					{
						POINT point;

						point.x = pt.x;
						point.y = pt.y;
						RepositionLocalFiles(&point);
					}
					else if(dwEffect == DROPEFFECT_COPY)
					{
						IBufferManager	*pbmCopy = NULL;
						TCHAR			szFullFileName[MAX_PATH];
						int				i = 0;

						pbmCopy = new CBufferManager();

						for(i = 0;i < nDroppedFiles;i++)
						{
							/* Determine the name of the dropped file. */
							DragQueryFile((HDROP)pdf,i,szFullFileName,
								SIZEOF_ARRAY(szFullFileName));

							pbmCopy->WriteListEntry(szFullFileName);
						}

						CopyDroppedFilesInternal(pbmCopy,szDestDirectory,TRUE,TRUE);

						pbmCopy->Release();
					}
					else if(dwEffect == DROPEFFECT_LINK)
					{
						CreateShortcutsToDroppedFiles(pdf,szDestDirectory,nDroppedFiles);
					}
				}
				else
				{
					CopyDroppedFiles(pDataObject,pdf,(LPPOINT)&pt,
						szDestDirectory,grfKeyState,pdwEffect);
				}

				GlobalUnlock(stg.hGlobal);
			}
		}
	}

	if(m_bDeselectDropFolder)
	{
		ListView_SetItemState(m_hListView,
			m_iDropFolder,0,LVIS_SELECTED);
	}

	/* Remove the insertion mark from the listview. */
	ListView_HandleInsertionMark(m_hListView,0,NULL);

	m_bPerformingDrag = FALSE;

	return S_OK;
}

/* TODO: This isn't declared. */
int CALLBACK SortTemporaryStub(LPARAM lParam1,LPARAM lParam2,LPARAM lParamSort)
{
	CFolderView	*pFolderView = NULL;

	pFolderView = (CFolderView *)lParamSort;

	return pFolderView->SortTemporary(lParam1,lParam2);
}

int CALLBACK CFolderView::SortTemporary(LPARAM lParam1,LPARAM lParam2)
{
	return m_pExtraItemInfo[lParam1].iRelativeSort -
		m_pExtraItemInfo[lParam2].iRelativeSort;
}

void CFolderView::RepositionLocalFiles(POINT *ppt)
{
	list<DraggedFile_t>::iterator	itr;
	POINT							pt;
	POINT							ptOrigin;
	int								iItem;

	pt = *ppt;
	ScreenToClient(m_hListView,&pt);

	/* The auto arrange style must be off for the items
	to be moved. Therefore, if the style is on, turn it
	off, move the items, and the turn it back on. */
	if(m_bAutoArrange)
		ListView_SetAutoArrange(m_hListView,FALSE);

	for(itr = m_DraggedFilesList.begin();
		itr != m_DraggedFilesList.end();itr++)
	{
		iItem = LocateFileItemIndex(itr->szFileName);

		if(iItem != -1)
		{
			if(m_ViewMode == VM_DETAILS)
			{
				/* TODO: Disable or fix before release. */
				/*LVITEM lvItem;
				BOOL bRes;
				int nItems;
				int i = 0;

				nItems = ListView_GetItemCount(m_hListView);

				for(i = 0;i < nItems;i++)
				{
					lvItem.mask		= LVIF_PARAM;
					lvItem.iItem	= i;
					lvItem.iSubItem	= 0;
					bRes = ListView_GetItem(m_hListView,&lvItem);

					if(bRes)
					{
						m_pExtraItemInfo[(int)lvItem.lParam].iRelativeSort = 0;
					}
				}

				lvItem.mask		= LVIF_PARAM;
				lvItem.iItem	= iItem;
				lvItem.iSubItem	= 0;
				bRes = ListView_GetItem(m_hListView,&lvItem);

				if(bRes)
				{
					m_pExtraItemInfo[(int)lvItem.lParam].iRelativeSort = 1;
				}

				ListView_SortItems(m_hListView,SortTemporaryStub,(LPARAM)this);*/
			}
			else
			{
				/* If auto arrange is on, the dropped item(s) will
				have to be 'snapped' to the nearest item position.
				Otherwise, they may simply be placed where they are
				dropped. */
				if(m_bAutoArrange)
				{
					LVFINDINFO lvfi;
					LVHITTESTINFO lvhti;
					RECT rcItem;
					POINT ptNext;
					BOOL bRowEnd = FALSE;
					BOOL bRowStart = FALSE;
					int iNext;
					int iHitItem;
					int nItems;

					lvhti.pt = pt;
					iHitItem = ListView_HitTest(m_hListView,&lvhti);

					/* Based on ListView_HandleInsertionMark() code. */
					if(iHitItem != -1 && lvhti.flags & LVHT_ONITEM)
					{
						ListView_GetItemRect(m_hListView,lvhti.iItem,&rcItem,LVIR_BOUNDS);

						if((pt.x - rcItem.left) >
							((rcItem.right - rcItem.left)/2))
						{
							iNext = iHitItem;
						}
						else
						{
							/* Can just insert the item _after_ the item to the
							left, unless this is the start of a row. */
							iNext = ListView_GetNextItem(m_hListView,iHitItem,LVNI_TOLEFT);

							if(iNext == -1)
								iNext = iHitItem;

							bRowStart = (ListView_GetNextItem(m_hListView,iNext,LVNI_TOLEFT) == -1);
						}
					}
					else
					{
						lvfi.flags			= LVFI_NEARESTXY;
						lvfi.pt				= pt;
						lvfi.vkDirection	= VK_UP;
						iNext = ListView_FindItem(m_hListView,-1,&lvfi);

						if(iNext == -1)
						{
							lvfi.flags			= LVFI_NEARESTXY;
							lvfi.pt				= pt;
							lvfi.vkDirection	= VK_LEFT;
							iNext = ListView_FindItem(m_hListView,-1,&lvfi);
						}

						ListView_GetItemRect(m_hListView,iNext,&rcItem,LVIR_BOUNDS);

						if(pt.x > rcItem.left +
							((rcItem.right - rcItem.left)/2))
						{
							if(pt.y > rcItem.bottom)
							{
								int iBelow;

								iBelow = ListView_GetNextItem(m_hListView,iNext,LVNI_BELOW);

								if(iBelow != -1)
									iNext = iBelow;
							}

							bRowEnd = TRUE;
						}

						nItems = ListView_GetItemCount(m_hListView);

						ListView_GetItemRect(m_hListView,nItems - 1,&rcItem,LVIR_BOUNDS);

						if((pt.x > rcItem.left + ((rcItem.right - rcItem.left)/2)) &&
							pt.x < rcItem.right + ((rcItem.right - rcItem.left)/2) + 2 &&
							pt.y > rcItem.top)
						{
							iNext = nItems - 1;

							bRowEnd = TRUE;
						}

						if(!bRowEnd)
						{
							int iLeft;

							iLeft = ListView_GetNextItem(m_hListView,iNext,LVNI_TOLEFT);

							if(iLeft != -1)
								iNext = iLeft;
							else
								bRowStart = TRUE;
						}
					}

					ListView_GetItemPosition(m_hListView,iNext,&ptNext);

					/* Offset by 1 pixel in the x-direction. This ensures that
					the dropped item will always be placed AFTER iNext. */
					if(bRowStart)
					{
						/* If at the start of a row, simply place at x = 0
						so that dropped item will be placed before first
						item... */
						ListView_SetItemPosition32(m_hListView,
							iItem,0,ptNext.y);
					}
					else
					{
						ListView_SetItemPosition32(m_hListView,
							iItem,ptNext.x + 1,ptNext.y);
					}
				}
				else
				{
					ListView_GetOrigin(m_hListView,&ptOrigin);

					/* ListView may be scrolled horizontally or vertically. */
					ListView_SetItemPosition32(m_hListView,
						iItem,ptOrigin.x + pt.x - m_ptDraggedOffset.x,
						ptOrigin.y + pt.y - m_ptDraggedOffset.y);
				}
			}
		}
	}

	if(m_bAutoArrange)
		ListView_SetAutoArrange(m_hListView,TRUE);

	m_bDragging = FALSE;

	m_bPerformingDrag = FALSE;
}

void CFolderView::CopyDroppedFiles(IDataObject *pDataObject,
DROPFILES *pdf,POINT *ppt,TCHAR *szDestDirectory,DWORD grfKeyState,
DWORD *pdwEffect)
{
	IBufferManager	*pbmCopy = NULL;
	IBufferManager	*pbmMove = NULL;
	DroppedFile_t	DroppedFile;
	POINT			ptOrigin;
	POINT			LocalDropPoint;
	TCHAR			szFullFileName[MAX_PATH];
	DWORD			dwEffect;
	BOOL			bOnSameDrive;
	int				nDroppedFiles;
	int				i = 0;

	pbmCopy = new CBufferManager();
	pbmMove = new CBufferManager();

	nDroppedFiles = DragQueryFile((HDROP)pdf,0xFFFFFFFF,NULL,NULL);

	for(i = 0;i < nDroppedFiles;i++)
	{
		/* Determine the name of the dropped file. */
		DragQueryFile((HDROP)pdf,i,szFullFileName,
			SIZEOF_ARRAY(szFullFileName));

		bOnSameDrive = CheckItemLocations(pDataObject,i);

		dwEffect = DetermineCurrentDragEffect(grfKeyState,
			*pdwEffect,m_bDataAccept,bOnSameDrive);

		if(dwEffect == DROPEFFECT_MOVE)
			pbmMove->WriteListEntry(szFullFileName);
		else if(dwEffect == DROPEFFECT_COPY)
			pbmCopy->WriteListEntry(szFullFileName);
		else if(dwEffect == DROPEFFECT_LINK)
			CreateShortcutToDroppedFile(szDestDirectory,szFullFileName);

		/* Don't add the item to the list of files
		to be selected if it was dragged over another
		folder (i.e. it is not going into this folder
		directly). */
		if(!m_bOverFolder)
		{
			StringCchCopy(DroppedFile.szFileName,
				SIZEOF_ARRAY(DroppedFile.szFileName),szFullFileName);
			PathStripPath(DroppedFile.szFileName);

			ListView_GetOrigin(m_hListView,&ptOrigin);

			LocalDropPoint = *ppt;

			ScreenToClient(m_hListView,(LPPOINT)&LocalDropPoint);

			/* Store the coordinates of the dropped item. */
			DroppedFile.DropPoint.x = ptOrigin.x + LocalDropPoint.x;
			DroppedFile.DropPoint.y = ptOrigin.y + LocalDropPoint.y;

			m_DroppedFileNameList.push_back(DroppedFile);
		}
	}

	/* When dragging and dropping, any dropped items
	will be selected, while any previously selected
	items will be deselected. */
	/* TODO: May need to modify this in case there
	was an error with the drop (i.e. don't deselect current
	files if nothing was actually copied/moved). */
	if(!m_bOverFolder)
		ListView_DeselectAllItems(m_hListView);

	CopyDroppedFilesInternal(pbmCopy,szDestDirectory,TRUE,FALSE);
	CopyDroppedFilesInternal(pbmMove,szDestDirectory,FALSE,FALSE);

	pbmCopy->Release();
	pbmMove->Release();
}

void CFolderView::CopyDroppedFilesInternal(IBufferManager *pbm,
TCHAR *szDestDirectory,BOOL bCopy,BOOL bRenameOnCollision)
{
	SHFILEOPSTRUCT	shfo;
	TCHAR			*szFileNameList = NULL;
	DWORD			dwBufferSize;

	pbm->QueryBufferSize(&dwBufferSize);

	if(dwBufferSize > 1)
	{
		szFileNameList = (TCHAR *)malloc(dwBufferSize * sizeof(TCHAR));

		if(szFileNameList != NULL)
		{
			pbm->QueryBuffer(szFileNameList,dwBufferSize);

			m_bPositionDropItems = TRUE;

			shfo.hwnd	= m_hOwner;
			shfo.wFunc	= bCopy == TRUE ? FO_COPY : FO_MOVE;
			shfo.pFrom	= szFileNameList;
			shfo.pTo	= szDestDirectory;
			shfo.fFlags	= bRenameOnCollision == TRUE ? FOF_RENAMEONCOLLISION : 0;
			SHFileOperation(&shfo);

			free(szFileNameList);
		}
	}
}

void CFolderView::CreateShortcutsToDroppedFiles(DROPFILES *pdf,
TCHAR *szDestDirectory,int nDroppedFiles)
{
	TCHAR	szFullFileName[MAX_PATH];
	TCHAR	szLink[MAX_PATH];
	TCHAR	szFileName[MAX_PATH];
	int		i = 0;

	for(i = 0;i < nDroppedFiles;i++)
	{
		/* Determine the name of the dropped file. */
		DragQueryFile((HDROP)pdf,i,szFullFileName,
			SIZEOF_ARRAY(szFullFileName));

		StringCchCopy(szFileName,SIZEOF_ARRAY(szFileName),szFullFileName);
		PathStripPath(szFileName);
		PathRenameExtension(szFileName,_T(".lnk"));
		StringCchCopy(szLink,SIZEOF_ARRAY(szLink),szDestDirectory);
		PathAppend(szLink,szFileName);

		CreateLinkToFile(szFullFileName,szLink,EMPTY_STRING);
	}
}

void CFolderView::CreateShortcutToDroppedFile(TCHAR *szDestDirectory,
TCHAR *szFullFileName)
{
	TCHAR	szLink[MAX_PATH];
	TCHAR	szFileName[MAX_PATH];

	StringCchCopy(szFileName,SIZEOF_ARRAY(szFileName),szFullFileName);
	PathStripPath(szFileName);
	PathRenameExtension(szFileName,_T(".lnk"));
	StringCchCopy(szLink,SIZEOF_ARRAY(szLink),szDestDirectory);
	PathAppend(szLink,szFileName);

	CreateLinkToFile(szFullFileName,szLink,EMPTY_STRING);
}

void CFolderView::ScrollListViewFromCursor(HWND hListView,POINT *CursorPos)
{
	RECT		rc;
	LONG_PTR	fStyle;

	fStyle = GetWindowLongPtr(hListView,GWL_STYLE);

	GetClientRect(hListView,&rc);

	/* The listview can be scrolled only if there
	is a scrollbar present. */
	if((fStyle & WS_HSCROLL) == WS_HSCROLL)
	{
		if(CursorPos->x < MIN_X_POS)
			ListView_Scroll(hListView,-X_SCROLL_AMOUNT,0);
		else if(CursorPos->x > (rc.right - MIN_X_POS))
			ListView_Scroll(hListView,X_SCROLL_AMOUNT,0);
	}
	
	/* The listview can be scrolled only if there
	is a scrollbar present. */
	if((fStyle & WS_VSCROLL) == WS_VSCROLL)
	{
		if(CursorPos->y < MIN_Y_POS)
			ListView_Scroll(hListView,0,-Y_SCROLL_AMOUNT);
		else if(CursorPos->y > (rc.bottom - MIN_Y_POS))
			ListView_Scroll(hListView,0,Y_SCROLL_AMOUNT);
	}
}
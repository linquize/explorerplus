#ifndef SHELLVIEW_INCLUDED
#define SHELLVIEW_INCLUDED

#include <list>
#include "iPathManager.h"
#include "../Helper/Helper.h"
#include "../Helper/DropHandler.h"
#include "../Helper/Macros.h"

#define WM_USER_UPDATEWINDOWS		(WM_APP + 17)
#define WM_USER_FILESADDED			(WM_APP + 51)
#define WM_USER_STARTEDBROWSING		(WM_APP + 55)
#define WM_USER_NEWITEMINSERTED		(WM_APP + 200)
#define WM_USER_FOLDEREMPTY			(WM_APP + 201)
#define WM_USER_FILTERINGAPPLIED	(WM_APP + 202)
#define WM_USER_GETCOLUMNNAMEINDEX	(WM_APP + 203)
#define WM_USER_DIRECTORYMODIFIED	(WM_APP + 204)

typedef struct
{
	unsigned int id;
	BOOL bChecked;
	int iWidth;
} Column_t;

typedef struct
{
	unsigned int id;
	BOOL bChecked;
} ColumnOld_t;

typedef struct
{
	std::list<Column_t>	RealFolderColumnList;
	std::list<Column_t>	MyComputerColumnList;
	std::list<Column_t>	ControlPanelColumnList;
	std::list<Column_t>	RecycleBinColumnList;
	std::list<Column_t>	PrintersColumnList;
	std::list<Column_t>	NetworkConnectionsColumnList;
	std::list<Column_t>	MyNetworkPlacesColumnList;
} ColumnExport_t;

typedef struct
{
	UINT	SortMode;
	UINT	ViewMode;
	BOOL	bSortAscending;
	BOOL	bShowInGroups;
	BOOL	bShowHidden;
	BOOL	bAutoArrange;
	BOOL	bGridlinesActive;
	BOOL	bApplyFilter;
	BOOL	bFilterCaseSensitive;
	BOOL	bShowFolderSizes;
	BOOL	bDisableFolderSizesNetworkRemovable;
	BOOL	bHideSystemFiles;
	BOOL	bHideLinkExtension;
	BOOL	bForceSize;
	SizeDisplayFormat_t	sdf;
	TCHAR	szFilter[512];

	/* Initial columns. */
	std::list<Column_t>	*pRealFolderColumnList;
	std::list<Column_t>	*pMyComputerColumnList;
	std::list<Column_t>	*pControlPanelColumnList;
	std::list<Column_t>	*pRecycleBinColumnList;
	std::list<Column_t>	*pPrintersColumnList;
	std::list<Column_t>	*pNetworkConnectionsColumnList;
	std::list<Column_t>	*pMyNetworkPlacesColumnList;
} InitialSettings_t;

typedef struct
{
	BOOL bShowExtensions;
	BOOL bShowSizesInBytes;
	BOOL bShowFriendlyDates;
	BOOL bShowFolderSizes;
} GlobalSettings_t;

typedef struct
{
	ULARGE_INTEGER TotalFolderSize;
	ULARGE_INTEGER TotalSelectionSize;
} FolderInfo_t;

typedef enum
{
	FSM_NAME				= 1,
	FSM_DATEMODIFIED		= 2,
	FSM_SIZE				= 3,
	FSM_TYPE				= 4,
	FSM_TOTALSIZE			= 5,
	FSM_FREESPACE			= 6,
	FSM_COMMENTS			= 7,
	FSM_DATEDELETED			= 8,
	FSM_ORIGINALLOCATION	= 9,
	FSM_ATTRIBUTES			= 10,
	FSM_REALSIZE			= 11,
	FSM_SHORTNAME			= 12,
	FSM_OWNER				= 13,

	FSM_PRODUCTNAME			= 14,
	FSM_COMPANY				= 15,
	FSM_DESCRIPTION			= 16,
	FSM_FILEVERSION			= 17,
	FSM_PRODUCTVERSION		= 18,

	FSM_SHORTCUTTO			= 19,
	FSM_HARDLINKS			= 20,
	FSM_EXTENSION			= 21,
	FSM_CREATED				= 22,
	FSM_ACCESSED			= 23,

	FSM_TITLE				= 24,
	FSM_SUBJECT				= 25,
	FSM_AUTHOR				= 26,
	FSM_KEYWORDS			= 27,

	FSM_CAMERAMODEL			= 29,
	FSM_DATETAKEN			= 30,
	FSM_WIDTH				= 31,
	FSM_HEIGHT				= 32,

	FSM_VIRTUALCOMMENTS		= 33,

	FSM_FILESYSTEM			= 34,
	FSM_VIRTUALTYPE			= 35,

	FSM_NUMPRINTERDOCUMENTS	= 36,
	FSM_PRINTERSTATUS		= 37,
	FSM_PRINTERCOMMENTS		= 38,
	FSM_PRINTERLOCATION		= 39,

	FSM_NETWORKADAPTER_STATUS	= 40
} SORT_MODES;

typedef enum
{
	VM_ICONS				= 1,
	VM_SMALLICONS			= 2,
	VM_LIST					= 3,
	VM_DETAILS				= 4,
	VM_TILES				= 5,
	VM_THUMBNAILS			= 6,
	VM_EXTRALARGEICONS		= 7,
	VM_LARGEICONS			= 8,
} VIEW_MODES;

typedef enum
{
	CM_NAME					= 1,
	CM_TYPE					= 2,
	CM_SIZE					= 3,
	CM_DATEMODIFIED			= 4,
	CM_ATTRIBUTES			= 5,
	CM_REALSIZE				= 6,
	CM_SHORTNAME			= 7,
	CM_OWNER				= 8,

	/*File version information.*/
	CM_PRODUCTNAME			= 9,
	CM_COMPANY				= 10,
	CM_DESCRIPTION			= 11,
	CM_FILEVERSION			= 12,
	CM_PRODUCTVERSION		= 13,

	CM_SHORTCUTTO			= 14,
	CM_HARDLINKS			= 15,
	CM_EXTENSION			= 16,
	CM_CREATED				= 17,
	CM_ACCESSED				= 18,

	/* File summary information. */
	CM_TITLE				= 19,
	CM_SUBJECT				= 20,
	CM_AUTHOR				= 21,
	CM_KEYWORDS				= 22,
	CM_COMMENT				= 23,

	/* Photo data. */
	CM_CAMERAMODEL			= 24,
	CM_DATETAKEN			= 25,
	CM_WIDTH				= 26,
	CM_HEIGHT				= 27,

	/* Control panel. */
	CM_VIRTUALCOMMENTS		= 28,

	/* My Computer. */
	CM_TOTALSIZE			= 29,
	CM_FREESPACE			= 30,
	CM_FILESYSTEM			= 31,
	CM_VIRTUALTYPE			= 32,

	/* Recycle Bin. */
	CM_ORIGINALLOCATION		= 33,
	CM_DATEDELETED			= 34,

	/* Printer columns. */
	CM_NUMPRINTERDOCUMENTS	= 35,
	CM_PRINTERSTATUS		= 36,
	CM_PRINTERCOMMENTS		= 37,
	CM_PRINTERLOCATION		= 38,

	/* Network connections columns. */
	CM_NETWORKADAPTER_STATUS	= 39,

	/* Media metadata. */
	//CM_MEDIA_TITLE
	//CM_MEDIA_SUBTITLE
	//CM_MEDIA_WIDTH
	//CM_MEDIA_HEIGHT
	CM_MEDIA_BITRATE		= 40,
	CM_MEDIA_COPYRIGHT		= 41,
	CM_MEDIA_DURATION		= 42,
	CM_MEDIA_PROTECTED		= 43,
	CM_MEDIA_RATING			= 44,
	CM_MEDIA_ALBUMARTIST	= 45,
	CM_MEDIA_ALBUM			= 46,
	CM_MEDIA_BEATSPERMINUTE	= 47,
	CM_MEDIA_COMPOSER		= 48,
	CM_MEDIA_CONDUCTOR		= 49,
	CM_MEDIA_DIRECTOR		= 50,
	CM_MEDIA_GENRE			= 51,
	CM_MEDIA_LANGUAGE		= 52,
	CM_MEDIA_BROADCASTDATE	= 53,
	CM_MEDIA_CHANNEL		= 54,
	CM_MEDIA_STATIONNAME	= 55,
	CM_MEDIA_MOOD			= 56,
	CM_MEDIA_PARENTALRATING	= 57,
	CM_MEDIA_PARENTALRATINGREASON	= 58,
	CM_MEDIA_PERIOD			= 59,
	CM_MEDIA_PRODUCER		= 60,
	CM_MEDIA_PUBLISHER		= 61,
	CM_MEDIA_WRITER			= 62,
	CM_MEDIA_YEAR			= 63,

	/* Printer columns. */
	CM_PRINTERMODEL			= 64
} COLUMNS;

class CItemObject
{
public:

	LPITEMIDLIST	pridl;
	TCHAR			szDisplayName[MAX_PATH];
	BOOL			bReal;
	BOOL			bIconRetrieved;
	BOOL			bThumbnailRetreived;
	int				iIcon;

	/* Only used for folders. Records whether
	the folders size has been retrieved yet. */
	BOOL			bFolderSizeRetrieved;

	/* These are only used for drives. They are
	needed for when a drive is removed from the
	system, in which case the drive name is needed
	so that the removed drive can be found. */
	BOOL			bDrive;
	TCHAR			szDrive[4];

	/* Used for temporary sorting in details mode (i.e.
	when items need to be rearranged). */
	int				iRelativeSort;
};

typedef struct
{
	TCHAR szHeader[512];
	int iGroupId;

	/* Used to record the number of items in this group.
	Mimics the feature available in Windows Vista and later. */
	int nItems;
} TypeGroup_t;

class CFolderView : public IDropTarget, public IDropFilesCallback
{
public:

	static CFolderView	*CreateNew(HWND hOwner,HWND hListView,InitialSettings_t *pSettings,HANDLE hIconThread,HANDLE hFolderSizeThread);

	/* IUnknown methods. */
	HRESULT __stdcall	QueryInterface(REFIID iid,void **ppvObject);
	ULONG __stdcall		AddRef(void);
	ULONG __stdcall		Release(void);

	/* Navigation. */
	HRESULT				BrowseFolder(LPITEMIDLIST pidlDirectory,UINT wFlags);
	HRESULT				BrowseFolder(TCHAR *szPath,UINT wFlags);
	HRESULT				Refresh(void);

	/* Drag and Drop. */
	void				DragStarted(int iFirstItem,POINT *ptCursor);
	void				DragStopped(void);
	HRESULT _stdcall	DragEnter(IDataObject *pDataObject,DWORD grfKeyState,POINTL pt,DWORD *pdwEffect);
	HRESULT _stdcall	DragOver(DWORD grfKeyState,POINTL pt,DWORD *pdwEffect);
	HRESULT _stdcall	DragLeave(void);
	HRESULT _stdcall	Drop(IDataObject *pDataObject,DWORD grfKeyState,POINTL ptl,DWORD *pdwEffect);

	/* Drag and Drop support. */
	BOOL				QueryDragging(void) const;

	/* Get/Set current state. */
	LPITEMIDLIST		QueryCurrentDirectoryIdl(void) const;
	UINT				QueryCurrentDirectory(int BufferSize,TCHAR *Buffer) const;
	BOOL				GetAutoArrange(void) const;
	HRESULT				SortFolder(UINT SortMode);
	HRESULT				SetCurrentViewMode(DWORD ViewMode);
	HRESULT				GetCurrentViewMode(UINT *pViewMode) const;
	HRESULT				GetSortMode(UINT *SortMode) const;
	HRESULT				SetSortMode(UINT SortMode);
	BOOL				IsGroupViewEnabled(void) const;
	BOOL				ToggleSortAscending(void);
	BOOL				GetSortAscending(void) const;
	BOOL				SetSortAscending(BOOL bAscending);
	BOOL				ToggleAutoArrange(void);
	BOOL				QueryAutoArrange(void) const;
	BOOL				QueryShowHidden(void) const;
	BOOL				SetShowHidden(BOOL bShowHidden);
	BOOL				ToggleShowHidden(void);
	BOOL				IsBackHistory(void) const;
	BOOL				IsForwardHistory(void) const;
	void				GetBackHistory(std::list<LPITEMIDLIST> *lHistory) const;
	void				GetForwardHistory(std::list<LPITEMIDLIST> *lHistory) const;
	LPITEMIDLIST		RetrieveHistoryItemWithoutUpdate(int iItem);
	LPITEMIDLIST		RetrieveHistoryItem(int iItem);
	BOOL				CanBrowseUp(void) const;
	int					QueryNumItems(void) const;
	int					QueryNumSelectedFiles(void) const;
	int					QueryNumSelectedFolders(void) const;
	int					QueryNumSelected(void) const;

	/* Settings. */
	void				SetUserOptions(InitialSettings_t *is);
	void				SetGlobalSettings(GlobalSettings_t *gs);

	/* ID. */
	int					GetId(void) const;
	void				SetId(int ID);

	/* Directory modification support. */
	void				FilesModified(DWORD Action,TCHAR *FileName,int EventId,int iFolderIndex);
	void				DirectoryAltered(void);
	void				SetDirMonitorId(int iDirMonitorId);
	int					GetDirMonitorId(void) const;
	int					GetFolderIndex(void) const;

	/* Item information. */
	LPWIN32_FIND_DATA	QueryFileFindData(int iItem) const;
	LPITEMIDLIST		QueryItemRelativeIdl(int iItem) const;
	DWORD				QueryFileAttributes(int iItem) const;
	int					QueryDisplayName(int iItem,UINT BufferSize,TCHAR *Buffer) const;
	BOOL				IsFileReal(int iItem) const;
	HRESULT				QueryFullItemName(int iIndex,TCHAR *FullItemPath) const;
	
	/* Column support. */
	int					SetAllColumnData(void);
	void				ExportCurrentColumns(std::list<Column_t> *pColumns);
	void				ImportColumns(std::list<Column_t> *pColumns,BOOL bColumnsSwapped);

	/* Thumbnails view. */
	int					GetExtractedThumbnail(HBITMAP hThumbnailBitmap);

	/* Folder size support. */
	int					SetAllFolderSizeColumnData(void);

	/* Filtering. */
	void				GetFilter(TCHAR *szFilter,int cchMax) const;
	void				SetFilter(TCHAR *szFilter);
	BOOL				GetFilterStatus(void) const;
	void				SetFilterStatus(BOOL bFilter);
	BOOL				GetFilterCaseSensitive(void) const;
	void				SetFilterCaseSensitive(BOOL bCaseSensitive);

	void				UpdateFileSelectionInfo(int,BOOL);
	HRESULT				CreateHistoryPopup(IN HWND hParent,OUT LPITEMIDLIST *pidl,IN POINT *pt,IN BOOL bBackOrForward);
	int					SelectFiles(TCHAR *FileNamePattern);
	void				QueryFolderInfo(FolderInfo_t *pFolderInfo);
	int					LocateFileItemIndex(const TCHAR *szFileName) const;
	BOOL				DeghostItem(int iItem);
	BOOL				GhostItem(int iItem);
	void				OnListViewGetDisplayInfo(LPARAM lParam);
	void				AddToIconFinderQueue(LVITEM *plvItem);
	void				EmptyIconFinderQueue(void);
	void				AddToThumbnailFinderQueue(LPARAM lParam);
	void				EmptyThumbnailsQueue(void);
	BOOL				InVirtualFolder(void) const;
	BOOL				CanCreate(void) const;

	/* Column queueing. */
	void				AddToColumnQueue(int iItem);
	void				EmptyColumnQueue(void);
	BOOL				RemoveFromColumnQueue(int *iItem);

	/* Folder size queueing. */
	void				AddToFolderQueue(int iItem);
	void				EmptyFolderQueue(void);
	BOOL				RemoveFromFolderQueue(int *iItem);

	/* Listview sorting. */
	int CALLBACK		Sort(LPARAM lParam1,LPARAM lParam2) const;
	int					SortByDate(LPARAM lParam1,LPARAM lParam2,int DateType) const;
	int CALLBACK		SortByName(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortBySize(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByType(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByDateModified(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByTotalSize(LPARAM lParam1,LPARAM lParam2,BOOL bTotalSize) const;
	int CALLBACK		SortByComments(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByDateDeleted(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByOriginalLocation(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByAttributes(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByRealSize(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByShortName(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByOwner(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByProductName(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByCompany(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByDescription(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByFileVersion(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByProductVersion(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByVersionInfo(LPARAM lParam1,LPARAM lParam2,int VersionProperty) const;
	int CALLBACK		SortByShortcutTo(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByHardlinks(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByExtension(LPARAM lParam1,LPARAM lParam2) const;
	int	CALLBACK		SortByDateCreated(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByDateAccessed(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByTitle(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortBySubject(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByAuthor(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByKeywords(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortBySummaryProperty(LPARAM lParam1,LPARAM lParam2,DWORD dwPropertyType) const;
	int CALLBACK		SortByCameraModel(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByDateTaken(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByWidth(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByHeight(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByImageProperty(LPARAM lParam1,LPARAM lParam2,PROPID PropertyId) const;
	int CALLBACK		SortByVirtualComments(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByFileSystem(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByVirtualType(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByNumPrinterDocuments(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByPrinterStatus(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByPrinterComments(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByPrinterLocation(LPARAM lParam1,LPARAM lParam2) const;
	int CALLBACK		SortByNetworkAdapterStatus(LPARAM lParam1,LPARAM lParam2) const;

	void				ToggleGrouping(void);
	void				SetGrouping(BOOL bShowInGroups);
	void				SetGroupingFlag(BOOL bShowInGroups);

	void				SetHideSystemFiles(BOOL bHideSystemFiles);
	void				SetShowExtensions(BOOL bShowExtensions);
	void				SetHideLinkExtension(BOOL bHideLinkExtension);
	void				SetShowFolderSizes(BOOL bShowFolderSizes);
	void				SetDisableFolderSizesNetworkRemovable(BOOL bDisableFolderSizesNetworkRemovable);
	void				SetShowFriendlyDates(BOOL bShowFriendlyDates);
	void				SetInsertSorted(BOOL bInsertSorted);
	void				SetForceSize(BOOL bForceSize);
	void				SetSizeDisplayFormat(SizeDisplayFormat_t sdf);

	int CALLBACK		SortTemporary(LPARAM lParam1,LPARAM lParam2);

	BOOL				GetTerminationStatus(void) const;
	void				SetTerminationStatus(void);

	void				ColumnClicked(int iClickedColumn);
	void				QueryCurrentSortModes(std::list<int> *pSortModes) const;
	size_t				QueryNumActiveColumns(void) const;
	void				ToggleGridlines(void);
	BOOL				QueryGridlinesActive(void) const;
	void				SetResourceModule(HINSTANCE hResourceModule);
	void				ImportAllColumns(ColumnExport_t *pce);
	void				ExportAllColumns(ColumnExport_t *pce);
	void				QueueRename(LPCITEMIDLIST pidlItem);
	void				SelectItems(const std::list<std::wstring> &PastedFileList);
	void				RefreshAllIcons(void);
	void				OnDeviceChange(WPARAM wParam,LPARAM lParam);

private:

	DISALLOW_COPY_AND_ASSIGN(CFolderView);

	typedef struct
	{
		TCHAR	szFileName[MAX_PATH];
		DWORD	dwAction;
		int		iFolderIndex;
	} AlteredFile_t;

	typedef struct
	{
		int		iItem;
		int		iItemInternal;

		BOOL	bPosition;
		int		iAfter;
	} AwaitingAdd_t;

	typedef struct
	{
		TCHAR szFileName[MAX_PATH];
	} Added_t;

	typedef struct
	{
		TCHAR szFileName[MAX_PATH];
		POINT DropPoint;
	} DroppedFile_t;

	typedef struct
	{
		TCHAR szFileName[MAX_PATH];
	} DraggedFile_t;

	CFolderView(HWND hOwner,HWND hListView,InitialSettings_t *pSettings,HANDLE hIconThread,HANDLE hFolderSizeThread);
	~CFolderView();

	void				InitializeItemMap(int iStart,int iEnd);
	int					GenerateUniqueItemId(void);
	BOOL				GhostItemInternal(int iItem,BOOL bGhost);
	void				DetermineFolderVirtual(LPITEMIDLIST pidlDirectory);
	void				VerifySortMode(void);
	void				AllocateInitialItemMemory(void);

	/* Browsing support. */
	int					BrowseVirtualFolder(TCHAR *szParsingName);
	int					BrowseVirtualFolder(LPITEMIDLIST pidlDirectory);
	HRESULT				ParsePath(LPITEMIDLIST *pidlDirectory,UINT uFlags,BOOL *bWriteHistory);
	void inline			InsertAwaitingItems(BOOL bInsertIntoGroup);
	BOOL				IsFileFiltered(int iItemInternal) const;
	TCHAR				*ProcessItemFileName(int iItemInternal);
	HRESULT inline		AddItemInternal(LPITEMIDLIST pidlDirectory,LPITEMIDLIST pidlRelative,TCHAR *szFileName,int iItemIndex,BOOL bPosition);
	HRESULT inline		AddItemInternal(int iItemIndex,int iItemId,BOOL bPosition);
	int inline			SetItemInformation(LPITEMIDLIST pidlDirectory,LPITEMIDLIST pidlRelative,TCHAR *szFileName);
	void				ResetFolderMemoryAllocations(void);
	void				SetCurrentViewModeInternal(DWORD ViewMode);

	/* Listview column support. */
	void				PlaceColumns(void);
	void				SetColumnData(unsigned int ColumnId,int iItem,int iColumnIndex);
	void				InsertColumn(unsigned int ColumnId,int iColumndIndex,int iWidth);
	void				SetActiveColumnSet(void);
	unsigned int		DetermineColumnSortMode(int iColumnId) const;
	void				GetColumnInternal(unsigned int id,Column_t *pci) const;
	void				SaveColumnWidths(void);

	/* Listview columns - set column data. */
	int					SetNameColumnData(HWND hListView,int iItem,int iColumn);
	int					SetSizeColumnData(HWND hListView,int iItem,int iColumn);
	int					SetRealSizeColumnData(HWND hListView,int iItem,int iColumn);
	int					SetTypeColumnData(HWND hListView,int iItem,int iColumn);
	void				SetVirtualTypeColumnData(int iItem,int iColumn);
	void				SetTotalSizeColumnData(int iItem,int iColumn,BOOL bTotalSize);
	void				SetFileSystemColumnData(int iItem,int iColumn);
	int					SetTimeColumnData(HWND hListView,int iItem,int iColumn,int TimeType);
	int					SetAttributeColumnData(HWND hListView,int iItem,int iColumn);
	int					SetShortNameColumnData(HWND hListView,int iItem,int iColumn);
	int					SetOwnerColumnData(HWND hListView,int iItem,int iColumn);
	int					SetVersionColumnData(HWND hListView,int iItem,int iColumn,TCHAR *lpszVersion);
	int					SetShortcutColumnData(HWND hListView,int iItem,int iColumn);
	int					SetHardLinksColumnData(HWND hListView,int iItem,int iColumn);
	int					SetExtensionColumnData(HWND hListView,int iItem,int iColumn);
	int					SetSummaryColumnData(HWND hListView,int iItem,int iColumn,DWORD dwPropertyType);
	int					SetImageColumnData(HWND hListView,int iItem,int iColumn,PROPID PropertyId);
	void				SetControlPanelComments(int iItem,int iColumn);
	void				SetNumPrinterDocumentsColumnData(int iItem,int iColumn);
	void				SetPrinterStatusColumnData(int iItem,int iColumn);
	void				SetPrinterCommentsColumnData(int iItem,int iColumn);
	void				SetPrinterLocationColumnData(int iItem,int iColumn);
	void				SetPrinterModelColumnData(int iItem,int iColumn);
	void				SetNetworkAdapterStatusColumnData(int iItem,int iColumn);
	void				SetMediaStatusColumnData(int iItem,int iColumn,int iType);

	/* Device change support. */
	void				UpdateDriveIcon(TCHAR *szDrive);
	void				RemoveDrive(TCHAR *szDrive);
	
	/* Directory altered support. */
	void				OnFileActionAdded(TCHAR *szFileName);
	void				RemoveItem(int iItemInternal);
	void				RemoveItemInternal(TCHAR *szFileName);
	void				ModifyItemInternal(TCHAR *FileName);
	void				OnFileActionRenamedOldName(TCHAR *szFileName);
	void				OnFileActionRenamedNewName(TCHAR *szFileName);
	void				RenameItem(int iItemInternal,TCHAR *szNewFileName);
	int					DetermineItemSortedPosition(LPARAM lParam) const;
	int					SortItemsRelative(LPARAM lParam1,LPARAM lParam2) const;
	int					DetermineRelativeItemPositions(LPARAM lParam1,LPARAM lParam2) const;

	/* Filtering support. */
	BOOL				IsFilenameFiltered(TCHAR *FileName) const;
	void				RemoveFilteredItems(void);
	void				RemoveFilteredItem(int iItem,int iItemInternal);
	void				UpdateFiltering(void);
	void				UnfilterAllItems(void);

	/* Listview group support (real files). */
	int					DetermineItemGroup(int iItemInternal);
	void				DetermineItemNameGroup(int iItemInternal,TCHAR *szGroupHeader,int cchMax) const;
	void				DetermineItemSizeGroup(int iItemInternal,TCHAR *szGroupHeader,int cchMax) const;
	void				DetermineItemDateGroup(int iItemInternal,int iDateType,TCHAR *szGroupHeader,int cchMax) const;
	void				DetermineItemAttributeGroup(int iItemInternal,TCHAR *szGroupHeader,int cchMax) const;
	void				DetermineItemOwnerGroup(int iItemInternal,TCHAR *szGroupHeader,int cchMax) const;
	void				DetermineItemVersionGroup(int iItemInternal,TCHAR *szVersionType,TCHAR *szGroupHeader,int cchMax) const;
	void				DetermineItemCameraPropertyGroup(int iItemInternal,PROPID PropertyId,TCHAR *szGroupHeader,int cchMax) const;
	void				DetermineItemExtensionGroup(int iItemInternal,TCHAR *szGroupHeader,int cchMax) const;
	void				DetermineItemFileSystemGroup(int iItemInternal,TCHAR *szGroupHeader,int cchMax) const;
	void				DetermineItemNetworkStatus(int iItemInternal,TCHAR *szGroupHeader,int cchMax) const;

	/* Listview group support (virtual files). */
	void				DetermineItemTypeGroupVirtual(int iItemInternal,TCHAR *szGroupHeader,int cchMax) const;
	void				DetermineItemTotalSizeGroup(int iItemInternal,TCHAR *szGroupHeader,int cchMax) const;
	void				DetermineItemFreeSpaceGroup(int iItemInternal,TCHAR *szGroupHeader,int cchMax) const;
	void				DetermineItemCommentGroup(int iItemInternal,DWORD dwPropertyType,TCHAR *szGroupHeader,int cchMax) const;

	/* Other grouping support. */
	int					CheckGroup(TCHAR *szGroupHeader,PFNLVGROUPCOMPARE pfnGroupCompare);
	void				InsertItemIntoGroup(int iItem,int iGroupId);
	void				MoveItemsIntoGroups(void);

	/* Thumbnails view. */
	void				SetupThumbnailsView(void);
	void				RemoveThumbnailsView(void);
	int					GetIconThumbnail(int iInternalIndex);
	int					GetThumbnailInternal(int iType,int iInternalIndex,HBITMAP hThumbnailBitmap);
	void				DrawIconThumbnailInternal(HDC hdcBacking,int iInternalIndex);
	void				DrawThumbnailInternal(HDC hdcBacking,HBITMAP hThumbnailBitmap);

	/* Tiles view. */
	void				InsertTileViewColumns(void);
	void				DeleteTileViewColumns(void);
	void				SetTileViewInfo(void);
	void				SetTileViewItemInfo(int iItem,int iItemInternal);

	/* Drag and Drop support. */
	HRESULT				InitializeDragDropHelpers(void);
	DWORD				CheckItemLocations(IDataObject *pDataObject,int iDroppedItem);
	void				HandleDragSelection(POINT *ppt);
	void				RepositionLocalFiles(POINT *ppt);
	void				ScrollListViewFromCursor(HWND hListView,POINT *CursorPos);
	void				PositionDroppedItems(void);
	void				OnDropFile(const std::list<std::wstring> &PastedFileList,POINT *ppt);

	/* Miscellaneous. */
	BOOL				CompareVirtualFolders(UINT uFolderCSIDL) const;
	int					LocateFileItemInternalIndex(const TCHAR *szFileName) const;
	HRESULT				RetrieveItemInfoTip(int iItem,TCHAR *szInfoTip,size_t cchMax);
	void				ApplyHeaderSortArrow(void);
	void				QueryFullItemNameInternal(int iItemInternal,TCHAR *szFullFileName) const;
	void				CopyColumnsInternal(std::list<Column_t> *pInternalColumns,std::list<Column_t> *pColumns);


	int					m_iRefCount;

	HWND				m_hListView;
	HWND				m_hOwner;

	BOOL				m_bPerformingDrag;
	BOOL				m_bNotifiedOfTermination;
	HIMAGELIST			m_hListViewImageList;

	/* Stores a WIN32_FIND_DATA structure for each file.
	Only valid for 'real' files. */
	WIN32_FIND_DATA *	m_pwfdFiles;

	/* Stores various extra information on files, such
	as display name. */
	CItemObject *		m_pExtraItemInfo;

	/* Manages browsing history. */
	CPathManager *		m_pPathManager;

	HANDLE				m_hThread;
	HANDLE				m_hFolderSizeThread;

	/* Internal state. */
	LPITEMIDLIST		m_pidlDirectory;
	HINSTANCE			m_hResourceModule;
	HANDLE				m_hIconEvent;
	TCHAR				m_CurDir[MAX_PATH];
	ULARGE_INTEGER		m_ulTotalDirSize;
	ULARGE_INTEGER		m_ulFileSelectionSize;
	DWORD				m_dwMajorVersion;
	UINT				m_SortMode;
	UINT				m_ViewMode;
	BOOL				m_bVirtualFolder;
	BOOL				m_bFolderVisited;
	BOOL				m_bShowFolderSizes;
	BOOL				m_bDisableFolderSizesNetworkRemovable;
	BOOL				m_bForceSize;
	SizeDisplayFormat_t	m_SizeDisplayFormat;
	int					m_nTotalItems;
	int					m_NumFilesSelected;
	int					m_NumFoldersSelected;
	int					m_iCurrentAllocation;
	int					m_iCachedPosition;
	int					m_iDirMonitorId;
	int					m_iFolderIcon;
	int					m_iFileIcon;
	int *				m_pItemMap;
	int					m_iDropped;

	/* Stores a unique index for each folder.
	This may be needed so that folders can be
	told apart when adding files from directory
	modification. */
	int					m_iUniqueFolderIndex;

	/* User options variables. */
	BOOL				m_bAutoArrange;
	BOOL				m_bShowInGroups;
	BOOL				m_bSortAscending;
	BOOL				m_bShowFriendlyDates;
	BOOL				m_bGridlinesActive;
	BOOL				m_bShowHidden;
	BOOL				m_bShowExtensions;
	BOOL				m_bHideSystemFiles;
	BOOL				m_bHideLinkExtension;
	BOOL				m_bInsertSorted;

	/* ID. */
	int					m_ID;

	/* Stores information on files that
	have been modified (i.e. created, deleted,
	renamed, etc). */
	CRITICAL_SECTION	m_csDirectoryAltered;
	std::list<AlteredFile_t>	m_AlteredList;
	std::list<Added_t>	m_FilesAdded;

	/* Stores information on files that have
	been created and are awaiting insertion
	into the listview. */
	std::list<AwaitingAdd_t>	m_AwaitingAddList;
	int					m_nAwaitingAdd;

	/* Shell new. */
	BOOL				m_bNewItemCreated;
	LPITEMIDLIST		m_pidlNewItem;
	int					m_iIndexNewItem;

	/* File selection. */
	std::list<std::wstring>	m_FileSelectionList;

	/* Column gathering information. */
	std::list<int>		m_pColumnInfoList;
	CRITICAL_SECTION	m_column_cs;
	HANDLE				m_hColumnQueueEvent;

	/* Folder size information. */
	std::list<int>		m_pFolderInfoList;
	CRITICAL_SECTION	m_folder_cs;
	HANDLE				m_hFolderQueueEvent;

	/* Thumbnails. */
	BOOL				m_bThumbnailsSetup;

	/* Column related data. */
	std::list<Column_t> *m_pActiveColumnList;
	std::list<Column_t>	m_RealFolderColumnList;
	std::list<Column_t>	m_MyComputerColumnList;
	std::list<Column_t>	m_ControlPanelColumnList;
	std::list<Column_t>	m_RecycleBinColumnList;
	std::list<Column_t>	m_PrintersColumnList;
	std::list<Column_t>	m_NetworkConnectionsColumnList;
	std::list<Column_t>	m_MyNetworkPlacesColumnList;
	BOOL				m_bColumnsPlaced;
	int					m_nCurrentColumns;
	int					m_nActiveColumns;
	unsigned int		m_iPreviousSortedColumnId;

	/* Drag and drop related data. */
	IDragSourceHelper *	m_pDragSourceHelper;
	IDropTargetHelper *	m_pDropTargetHelper;
	std::list<DroppedFile_t>	m_DroppedFileNameList;
	std::list<DraggedFile_t>	m_DraggedFilesList;
	DragTypes_t			m_DragType;
	POINT				m_ptDraggedOffset;
	BOOL				m_bDataAccept;
	BOOL				m_bDragging;
	BOOL				m_bDeselectDropFolder;
	BOOL				m_bOnSameDrive;
	int					m_bOverFolder;
	int					m_iDropFolder;

	/* Listview groups. The group id is declared
	explicitly, rather than taken from the size
	of the group list, to avoid warnings concerning
	size_t and int. */
	std::list<TypeGroup_t>	m_GroupList;
	int					m_iGroupId;

	/* Filtering related data. */
	std::list<int>		m_FilteredItemsList;
	TCHAR				m_szFilter[512];
	BOOL				m_bApplyFilter;
	BOOL				m_bFilterCaseSensitive;

	BOOL volatile		m_bBrowsing;
};

#endif
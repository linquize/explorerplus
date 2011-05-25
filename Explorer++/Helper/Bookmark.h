#ifndef BOOKMARK_INCLUDED
#define BOOKMARK_INCLUDED

#include <list>
#include <boost/variant.hpp>

namespace NBookmarks
{
	enum BookmarkType_t
	{
		TYPE_BOOKMARK,
		TYPE_FOLDER
	};
}

class CBookmark;
class CBookmarkFolder;

class CBookmarkFolder
{
public:

	CBookmarkFolder(const std::wstring &strName);
	~CBookmarkFolder();

	UINT			GetID();

	std::wstring	GetName();

	void			SetName(const std::wstring &strName);

	/* Returns true if this folder has *at least*
	one child folder. */
	bool			HasChildFolder();

	std::list<boost::variant<CBookmarkFolder,CBookmark>>::iterator	begin();
	std::list<boost::variant<CBookmarkFolder,CBookmark>>::iterator	end();

	void			InsertBookmark(const CBookmark &Bookmark);
	void			InsertBookmark(const CBookmark &Bookmark,std::size_t Position);
	void			InsertBookmarkFolder(const CBookmarkFolder &BookmarkFolder);
	void			InsertBookmarkFolder(const CBookmarkFolder &BookmarkFolder,std::size_t Position);

	void			RemoveBookmark();
	void			RemoveBookmarkFolder();

	/* Retrieves the bookmark item with the
	specified id. Item in this case may
	refer to either a bookmark or bookmark
	folder. */
	std::pair<void *,NBookmarks::BookmarkType_t>	GetBookmarkItem(UINT uID);

	void			GetIterator();

private:

	static UINT		m_IDCounter;
	UINT			m_ID;

	std::wstring	m_strName;

	/* Keeps track of the number of child
	folders that are added. Used purely as
	an optimization for the HasChildFolder()
	method above. */
	int				m_nChildFolders;

	/* These need to be able to be saved and read
	back from storage. */
	FILETIME		m_ftCreated;
	FILETIME		m_ftModified;

	/* List of child folders and bookmarks. Note that
	the ordering within this list defines the ordering
	between child items (i.e. there is no explicit
	ordering). */
	std::list<boost::variant<CBookmarkFolder,CBookmark>>	m_ChildList;
};

class CBookmark
{
public:

	CBookmark(const std::wstring &strName,const std::wstring &strLocation,const std::wstring &strDescription);
	~CBookmark();

	UINT			GetID();

	std::wstring	GetName();
	std::wstring	GetLocation();
	std::wstring	GetDescription();

	void			SetName(const std::wstring &strName);
	void			SetLocation(const std::wstring &strLocation);
	void			SetDescription(const std::wstring &strDescription);

private:

	static UINT		m_IDCounter;
	UINT			m_ID;

	std::wstring	m_strName;
	std::wstring	m_strLocation;
	std::wstring	m_strDescription;

	FILETIME		m_ftCreated;
	FILETIME		m_ftModified;
};

#endif
/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* CalendarLib.h : Calendar library header file
*
*********************************************************************/

#include <iostream>
#include <fstream>
#include <windows.h>

using namespace std;

#define BUG_1 1		// Integer overflow via addition
#define BUG_2 2		// Uninitialized variable
#define BUG_3 3		// Integer overflow via multiplication
#define BUG_4 4		// Double free
#define BUG_5 5		// Unvalidated length field
#define BUG_6 6		// NULL pointer dereference
#define BUG_7 7		// Typo in error-handling code causes hang
#define BUG_8 8		// Unchecked use of tainted data
#define BUG_9 9		// Format string bug
#define BUG_10 10	// String-based stack buffer overflow

#define TRYEXCEPT 31

#define EnableBug(x)		{ BugBitmask |= (1 << x); /*printf("->EnableBug(%d)\n", x);*/ }
#define DisableBug(x)		{ BugBitmask &= (~(1 << x)); /*printf("->DisableBug(%d)\n", x);*/ }
#define IsBugEnabled(x)		BugBitmask & (1 << x)
#define IsBugDisabled(x)	!(BugBitmask & (1 << x))

#define DllImport   __declspec( dllimport )

extern "C"
{
	DllImport unsigned int BugBitmask;

	HANDLE *ParseCalendarFileBuffer(unsigned char *in, size_t len);
	HRESULT MergeCalendars(void *dest, void *source);

	int GetCalendarEntryCount(HANDLE cal);
	HANDLE GetFirstCalendarEntry(HANDLE cal);
	HANDLE GetNextCalendarEntry(HANDLE entry);
	enum EntryType GetCalendarEntryType(HANDLE entry);

	HANDLE GetSender(HANDLE entry);
	char *GetContactName(HANDLE c);
	char *GetContactEmail(HANDLE c);
	
	HANDLE GetFirstRecipient(HANDLE entry);
	HANDLE GetNextRecipient(HANDLE c);
	
	char *GetLocation(HANDLE entry);
	
	char *GetTimeZone(HANDLE entry);
	
	HRESULT GetStartTime(HANDLE entry, int *hours, int *minutes, int *seconds);
	
	HRESULT GetStartDate(HANDLE entry, int *year, int *month, int *day);
	
	HRESULT GetDuration(HANDLE entry, int *hours, int *minutes, int *seconds);
	
	char *GetSubject(HANDLE entry);

	char *GetContent(HANDLE entry);
	char *GetContentType(HANDLE entry);
	unsigned int GetContentLength(HANDLE entry);
	unsigned int GetContentData(HANDLE entry, PVOID dst, unsigned int len);

	int GetAttachmentCount(HANDLE entry);
	HANDLE GetFirstAttachment(HANDLE entry);
	HANDLE GetNextAttachment(HANDLE a);
	char *GetAttachmentName(HANDLE a);
	unsigned int GetAttachmentBlobLength(HANDLE a);
	HRESULT GetAttachmentBlob(HANDLE a, void *p, unsigned int len);
}
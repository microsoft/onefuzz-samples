/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* CalendarStructures.h:  contains declarations of the internal
* structures populated with calendar data by the parser
*
*********************************************************************/

#include <windows.h>

enum CalStringType
{
	SHORTSTRING,
	LONGSTRING
};

typedef struct _LongCalString
{
	unsigned long Length;
	unsigned char *Value;
} LongCalString;

typedef struct _ShortCalString
{
	unsigned short Length;
	unsigned char *Value;
} ShortCalString;

typedef struct _CalString
{
	CalStringType StringType;
	union
	{
		LongCalString  Long;
		ShortCalString Short;
	};
} CalString;

typedef struct _CalDate
{
	int Year;
	int Month;
	int Day;
} CalDate;

typedef struct _CalTime
{
	int Hour;
	int Minute;
	int Second;
} CalTime;


typedef struct _Contact
{
	CalString *Name;
	CalString *Email;
	struct _Contact *NextContact;
} Contact;

typedef struct _Blob
{
	unsigned int Length;
	PVOID Data;
} Blob;

typedef struct _StructuredBlob
{
	unsigned int SegmentCount;
	unsigned int SegmentLength;
	unsigned int TotalLength;
	PVOID Data;
} StructuredBlob;

typedef struct _Attachment
{
	CalString *Name;
	Blob *Blob;
} Attachment;

typedef struct _Attachments
{
	int Count;
	Attachment *Attachment;
} Attachments;

typedef struct _CalendarEntry
{
	enum EntryType			EntryType;
	Contact					*Sender;
	Contact					*Recipient;
	CalString				*Location;
	CalString				*TimeZone;
	CalTime					*StartTime;
	CalDate					*StartDate;
	CalTime					*Duration;
	CalString				*Subject;
	CalString				*Content;
	CalString				*ContentType;
	Attachments				*Attachments;
	StructuredBlob			*StructuredBlob;
	struct _CalendarEntry	*PreviousEntry;
	struct _CalendarEntry	*NextEntry;
} CalendarEntry;

typedef struct _Calendar
{
	int Version;
	int EntryCount;
	CalendarEntry *Entry;
} Calendar;

//////////////////////////////////////////
//
// Functions against the structs
//
//////////////////////////////////////////

CalString *CreateCalString(enum CalStringType type);
CalString *CreateCalStringAndInit(enum CalStringType type, const char *p);
void DestroyCalString(CalString *s);

CalDate *CreateCalDate();
void DestroyCalDate(CalDate *d);

CalTime *CreateCalTime();
void DestroyCalTime(CalTime *t);

Blob *CreateBlob();
void DestroyBlob(Blob *b);

StructuredBlob *CreateStructuredBlob();
void DestroyStructuredBlob(StructuredBlob *b);

Attachment *CreateAttachment();
Attachments *CreateAttachments();
Attachment *CreateMultipleAttachment(int attachmentCount);
void DestroyAttachment(Attachment *pAttachment);
void DestroyAttachments(Attachments *pAttachments);

Contact *CreateContact();
void DestroyContact(Contact *c);

StructuredBlob *CreateStructuredBlob();
void DestroyStructuredBlob(StructuredBlob *pUnknown);

CalendarEntry *CreateCalendarEntry();
void DestroyCalendarEntry(CalendarEntry *pCalendar);

Calendar *CreateCalendar(int version, int entryCount);
void DestroyCalendar(void *pCalendar);
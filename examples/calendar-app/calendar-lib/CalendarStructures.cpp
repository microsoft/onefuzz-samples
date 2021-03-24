/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* CalendarStructures.cpp:  contains functions to create,
* copy and destroy internal calendar data structures
*
*********************************************************************/

#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include "CalendarStructures.h"

extern "C"
{
	extern unsigned int BugBitmask;
}

CalString *CreateCalString(enum CalStringType stringType)
{
	CalString *r = (CalString *)calloc(1, sizeof(CalString));
	if (!r) return r;
	r->StringType = stringType;
	return r;
}

CalString *CreateCalStringAndInit(enum CalStringType stringType, const char *p)
{
	CalString *s = CreateCalString(stringType);
	if (!s)
	{
		return NULL;
	}

	if (stringType == SHORTSTRING)
	{
		if (strlen(p) > 0xfffe)
		{
			goto ERROR_EXIT;
		}

		unsigned int len = strlen(p);
		s->Short.Value = (unsigned char *)calloc(1, len + 1);
		if (!s->Short.Value)
		{
			goto ERROR_EXIT;
		}

		s->Short.Length = len;
		memcpy(s->Short.Value, p, len);
	}
	else if (stringType == LONGSTRING)
	{
		unsigned int len = strlen(p);
		s->Long.Value = (unsigned char *)calloc(1, len + 1);
		if (!s->Long.Value)
		{
			goto ERROR_EXIT;
		}

		s->Long.Length = len;
		memcpy(s->Long.Value, p, s->Long.Length);
	}
	else
	{
		printf("Invalid CalStringType");
		goto ERROR_EXIT;
	}

	return s;

ERROR_EXIT:
	DestroyCalString(s);
	return NULL;
}

/// <summary>
/// Copies the content of an existing CalString object to a new one that's returned
/// </summary>
CalString *CopyCalString(CalString *src)
{
	CalString *dst = CreateCalString(src->StringType);
	if (!dst)
	{
		return NULL;
	}

	dst->StringType = src->StringType;

	if (src->StringType == SHORTSTRING)
	{
		dst->Short.Length = src->Short.Length;
		dst->Short.Value = (unsigned char *)malloc(dst->Short.Length + 1);
		if (!dst->Short.Value)
		{
			goto ERROR_EXIT;
		}
		memcpy(dst->Short.Value, src->Short.Value, dst->Short.Length + 1);
	}

	else if (src->StringType == LONGSTRING)
	{
		dst->Long.Length = src->Long.Length;
		dst->Long.Value = (unsigned char *)malloc(dst->Long.Length + 1);
		if (!dst->Long.Value)
		{
			goto ERROR_EXIT;
		}
		memcpy(dst->Long.Value, src->Long.Value, dst->Long.Length + 1);
	}
	else
	{
		printf("Invalid StringType");
		goto ERROR_EXIT;
	}

	return dst;

ERROR_EXIT:
	DestroyCalString(dst);
	return NULL;
}

void DestroyCalString(CalString *s)
{
	if (!s) return;
	if (s->StringType == SHORTSTRING)
	{
		free(s->Short.Value);
	}
	else if (s->StringType == LONGSTRING)
	{
		free(s->Long.Value);
	}
	free(s);
}

CalDate *CreateCalDate()
{
	CalDate *r = (CalDate *)calloc(1, sizeof(CalDate));
	return r;
}

/// <summary>
/// Copies the content of an existing CalDate object to a new one that's returned
/// </summary>
CalDate *CopyCalDate(CalDate *src)
{
	CalDate *dst = CreateCalDate();
	if (!dst)
	{
		return NULL;
	}
	dst->Year = src->Year;
	dst->Month = src->Month;
	dst->Day = src->Day;
	return dst;
}

void DestroyCalDate(CalDate *d)
{
	free(d);
	return;
}

CalTime *CreateCalTime()
{
	CalTime *r = (CalTime *)calloc(1, sizeof(CalTime));
	return r;
}

/// <summary>
/// Copies the content of an existing CalTime object to a new one that's returned
/// </summary>
CalTime *CopyCalTime(CalTime *pTime)
{
	CalTime *dst = CreateCalTime();
	if (!dst)
	{
		return NULL;
	}

	dst->Hour = pTime->Hour;
	dst->Minute = pTime->Minute;
	dst->Second = pTime->Second;
	return dst;
}

void DestroyCalTime(CalTime *t)
{
	free(t);
}

Blob *CreateBlob()
{
	Blob *r = (Blob *)calloc(1, sizeof(Blob));
	return r;
}

/// <summary>
/// Copies the content of an existing Blob object to a new one that's returned
/// </summary>
Blob *CopyBlob(Blob *src)
{
	Blob *dst = CreateBlob();
	if (!dst)
	{
		return NULL;
	}

	dst->Length = src->Length;
	dst->Data = malloc(dst->Length);
	if (!dst->Data)
	{
		goto ERROR_EXIT;
	}
	memcpy(dst->Data, src->Data, dst->Length);
	return dst;

ERROR_EXIT:
	DestroyBlob(dst);
	return NULL;
}

void DestroyBlob(Blob *b)
{
	if (!b) return;
	free(b->Data);
}

StructuredBlob *CreateStructuredBlob()
{
	StructuredBlob *u = (StructuredBlob *)calloc(1, sizeof(StructuredBlob));
	return u;
}

void DestroyStructuredBlob(StructuredBlob *pUnknown)
{
	if (!pUnknown) return;
	if (pUnknown->Data)
	{
		free(pUnknown->Data);
	}
	free(pUnknown);
}

Contact *CreateContact()
{
	Contact *r = (Contact *)calloc(1, sizeof(Contact));
	return r;
}

/// <summary>
/// Copies the content of an existing Contact object to a new one that's returned
/// </summary>
Contact *CopyContact(Contact *pContact)
{
#define MAX_RECURSION 1000
	static int count;

	Contact *dst = CreateContact();
	if (!dst)
	{
		return NULL;
	}

	dst->Email = CopyCalString(pContact->Email);
	if (!dst)
	{
		goto ERROR_EXIT;
	}

	dst->Name = CopyCalString(pContact->Name);
	if (!dst->Name)
	{
		goto ERROR_EXIT;
	}

	if (pContact->NextContact)
	{
		dst->NextContact = CopyContact(pContact->NextContact); // <-- Recursive Call
		if (!dst->NextContact)
		{
			goto ERROR_EXIT;
		}
	}

	return dst;

ERROR_EXIT:
	DestroyContact(dst);
	return NULL;
}

void DestroyContact(Contact *pContact)
{
	// Free embedded structures (next ...)
	if (!pContact) return;

	do
	{
		if (pContact->Email)
		{
			DestroyCalString(pContact->Email);
		}

		if (pContact->Name)
		{
			DestroyCalString(pContact->Name);
		}

		Contact *next = pContact->NextContact;
		free(pContact);
		pContact = next;
	} while (pContact);

	return;
}

Attachment *CreateAttachment()
{
	Attachment *pAttachment = (Attachment *)calloc(1, sizeof(Attachment));
	return pAttachment;
}

Attachments *CreateAttachments()
{
	Attachments *r = (Attachments *)calloc(1, sizeof(Attachments));
	return r;
}

Attachment *CreateMultipleAttachment(int attachmentCount)
{
	Attachment *pAttachment = (Attachment *)calloc(attachmentCount, sizeof(Attachment));
	return pAttachment;
}

/// <summary>
/// Copies the content of an existing Attachment object to a new one that's returned
/// </summary>
Attachment CopyAttachment(Attachment dst)
{
	Attachment src;
	src.Name = CopyCalString(dst.Name);
	src.Blob = CopyBlob(dst.Blob);
	if (!src.Blob || !src.Name)
	{
		DestroyAttachment(&src);
		memset(&src, 0x00, sizeof(src));
	}
	return src;
}

/// <summary>
/// Copies the content of an existing Attachments object to a new one that's returned
/// </summary>
Attachments *CopyAttachments(Attachments *src)
{
	Attachments *pDest = CreateAttachments();
	if (!pDest)
	{
		return NULL;
	}

	pDest->Attachment = (Attachment *)calloc(1, pDest->Count * sizeof(Attachment));
	if (!pDest->Attachment)
	{
		goto ERROR_EXIT;
	}

	pDest->Count = src->Count;

	for (int i = 0; i < src->Count; i++)
	{
		pDest->Attachment[i] = CopyAttachment(src->Attachment[i]);
	}

	return pDest;

ERROR_EXIT:
	DestroyAttachments(pDest);
	return NULL;
}

void DestroyAttachment(Attachment *pAttachment)
{
	if (!pAttachment) return;

	if (pAttachment->Name)
	{
		DestroyCalString(pAttachment->Name);
	}

	if (pAttachment->Blob)
	{
		DestroyBlob(pAttachment->Blob);
	}
	return;
}

void DestroyAttachments(Attachments *pAttachments)
{
	// account for next field ...
	if (!pAttachments) return;

	int i;
	for (i = 0; i < pAttachments->Count; i++)
	{
		DestroyAttachment(&(pAttachments->Attachment[i])); // Bug #4: pAttachments has already been freed
	}

	free(pAttachments);
};

CalendarEntry *CreateCalendarEntry()
{
	CalendarEntry *r = (CalendarEntry *)calloc(1, sizeof(CalendarEntry));
	return r;
}

/// <summary>
/// Copies the content of an existing CalendarEntry object to a new one that's returned
/// </summary>
CalendarEntry *CopyCalendarEntry(CalendarEntry *pEntry)
{
	CalendarEntry *pEntryCopy = CreateCalendarEntry();
	if (!pEntryCopy)
	{
		return NULL;
	}

	pEntryCopy->EntryType = pEntry->EntryType;

	pEntryCopy->Sender = CopyContact(pEntry->Sender);
	if (!pEntryCopy->Sender)
	{
		goto ERROR_EXIT;
	}

	if (pEntry->Recipient)
	{
		pEntryCopy->Recipient = CopyContact(pEntry->Recipient);
		if (!pEntryCopy->Recipient)
		{
			goto ERROR_EXIT;
		}
	}

	if (pEntry->Location)
	{
		pEntryCopy->Location = CopyCalString(pEntry->Location);
		if (!pEntryCopy->Location)
		{
			goto ERROR_EXIT;
		}
	}

	pEntryCopy->TimeZone = CopyCalString(pEntry->TimeZone);
	if (!pEntryCopy->TimeZone)
	{
		goto ERROR_EXIT;
	}

	pEntryCopy->StartTime = CopyCalTime(pEntry->StartTime);
	if (!pEntryCopy->StartTime)
	{
		goto ERROR_EXIT;
	}

	pEntryCopy->StartDate = CopyCalDate(pEntry->StartDate);
	if (!pEntryCopy->StartDate)
	{
		goto ERROR_EXIT;
	}

	pEntryCopy->Duration = CopyCalTime(pEntry->Duration);
	if (!pEntryCopy->Duration)
	{
		goto ERROR_EXIT;
	}

	if (pEntry->Subject)
	{
		pEntryCopy->Subject = CopyCalString(pEntry->Subject);
		if (!pEntryCopy->Subject)
		{
			goto ERROR_EXIT;
		}
	}

	if (pEntry->Content)
	{
		pEntryCopy->Content = CopyCalString(pEntry->Subject);
		if (!pEntryCopy->Content)
		{
			goto ERROR_EXIT;
		}
	}

	if (pEntry->Attachments)
	{
		pEntryCopy->Attachments = CopyAttachments(pEntry->Attachments);
		if (!pEntryCopy->Attachments)
		{
			goto ERROR_EXIT;
		}
	}

	return pEntryCopy;

ERROR_EXIT:
	DestroyCalendarEntry(pEntryCopy);
	return NULL;
}

void DestroyCalendarEntry(CalendarEntry *pEntry)
{
	if (!pEntry) return;
	do
	{
		DestroyContact(pEntry->Sender);
		DestroyContact(pEntry->Recipient);
		DestroyCalString(pEntry->Location);
		DestroyCalString(pEntry->TimeZone);
		DestroyCalTime(pEntry->StartTime);
		DestroyCalDate(pEntry->StartDate);
		DestroyCalTime(pEntry->Duration);
		DestroyCalString(pEntry->Subject);
		DestroyCalString(pEntry->Content);
		DestroyCalString(pEntry->ContentType);
		DestroyAttachments(pEntry->Attachments);
		CalendarEntry *next = pEntry->NextEntry;
		free(pEntry);
		pEntry = next;
	} while (pEntry);
}

Calendar *CreateCalendar(int version, int entryCount)
{
	Calendar *r = (Calendar *)calloc(1, sizeof(Calendar));
	if (!r) return r;

	r->Version = version;
	r->EntryCount = entryCount;

	return r;
}

void DestroyCalendar(void *pCalendar)
{
	Calendar *c = (Calendar *)pCalendar;
	if (!pCalendar) return;

	CalendarEntry *e = c->Entry;
	DestroyCalendarEntry(e);
	free(pCalendar);
	return;
}
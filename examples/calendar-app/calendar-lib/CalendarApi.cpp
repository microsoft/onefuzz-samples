/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* CalendarApi.cpp:  Definitions of functions exported by
* CalendarLib.dll
*
*********************************************************************/

#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <fstream>
#include "CalendarStructures.h"
#include "CalendarParser.h"

using namespace std;

Calendar *ParseInput(unsigned char *in, size_t len);
CalendarEntry *CopyCalendarEntry(CalendarEntry *srcEntry);

#define DllExport   __declspec( dllexport )

extern "C"
{
	DllExport /*extern*/ unsigned int BugBitmask = ~0;

	DllExport Calendar *ParseCalendarFileBuffer(unsigned char *in, size_t len)
	{
		printf("-> Parsing CAL file buffer\n");
		return ParseInput(in, len);
	}

	DllExport HRESULT MergeCalendars(void *dest, void *source)
	{
		Calendar *dst = (Calendar *)dest;
		Calendar *src = (Calendar *)source;

		if (!dst || !src) return -1;
		if (src->Version != dst->Version) return -1;
		CalendarEntry *srcEntry = src->Entry;
		CalendarEntry *dstEntry = dst->Entry;

		CalendarEntry *temp = NULL, *copy = NULL;
		temp = CopyCalendarEntry(srcEntry);
		copy = temp;
		srcEntry = srcEntry->NextEntry;

		while (srcEntry)
		{
			if (temp) temp->NextEntry = CopyCalendarEntry(srcEntry); // todo, set prev
			if (!temp)
			{
				goto ERROR_EXIT;
			}

			temp = temp->NextEntry;
			srcEntry = srcEntry->NextEntry;
		}

		while (dstEntry->NextEntry) dstEntry = dstEntry->NextEntry;
		dstEntry->NextEntry = copy; // todo set prev
		return S_OK;

	ERROR_EXIT:
		DestroyCalendarEntry(copy);
		return S_FALSE;
	}

	DllExport int GetCalendarEntryCount(Calendar *pCalendar)
	{
		return pCalendar->EntryCount;
	}

	DllExport CalendarEntry *GetFirstCalendarEntry(Calendar *pCalendar)
	{
		return pCalendar->Entry;
	}

	DllExport CalendarEntry *GetNextCalendarEntry(CalendarEntry *pEntry)
	{
		if (!pEntry)
		{
			return NULL;
		}
		return pEntry->NextEntry;
	}

	DllExport enum EntryType GetCalendarEntryType(CalendarEntry *pEntry)
	{
		return pEntry->EntryType;
	}

	DllExport Contact *GetSender(CalendarEntry *pEntry)
	{
		return pEntry->Sender;
	}

	DllExport char *GetContactName(Contact *pContact)
	{
		return (char *)pContact->Name->Short.Value;
	}

	DllExport char *GetContactEmail(Contact *pContact)
	{
		return (char *)pContact->Email->Short.Value;
	}

	DllExport Contact *GetFirstRecipient(CalendarEntry *pEntry)
	{
		return pEntry->Recipient;
	}

	DllExport Contact *GetNextRecipient(Contact *pContact)
	{
		if (!pContact)
		{
			return NULL;
		}
		return pContact->NextContact;
	}

	DllExport char *GetLocation(CalendarEntry *pEntry)
	{
		if (pEntry->Location)
		{
			return (char *)pEntry->Location->Long.Value;
		}
		else return NULL;
	}

	DllExport HRESULT GetStartDate(CalendarEntry *pEntry, int *year, int *month, int *day)
	{
		if (!pEntry->StartDate || !year || !month || !day)
		{
			return S_FALSE;
		}

		*year = pEntry->StartDate->Year;
		*month = pEntry->StartDate->Month;
		*day = pEntry->StartDate->Day;

		return S_OK;
	}

	DllExport HRESULT GetStartTime(CalendarEntry *pEntry, int *hours, int *minutes, int *seconds)
	{
		if (!hours || !minutes || !seconds)
		{
			return S_FALSE;
		}

		*hours = pEntry->StartTime->Hour;
		*minutes = pEntry->StartTime->Minute;
		*seconds = pEntry->StartTime->Second;

		return S_OK;
	}

	DllExport char *GetTimeZone(CalendarEntry *pEntry)
	{
		return (char *)pEntry->TimeZone->Short.Value;
	}

	DllExport HRESULT GetDuration(CalendarEntry *pEntry, int *hours, int *minutes, int *seconds)
	{
		if (!hours || !minutes || !seconds)
		{
			return S_FALSE;
		}

		*hours = pEntry->Duration->Hour;
		*minutes = pEntry->Duration->Minute;
		*seconds = pEntry->Duration->Second;

		return S_OK;
	}

	DllExport char *GetSubject(CalendarEntry *pEntry)
	{
		if (pEntry->Subject)
		{
			return (char *)pEntry->Subject->Long.Value;
		}
		else return NULL;
	}

	DllExport char *GetContent(CalendarEntry *pEntry)
	{
		if (pEntry->Content)
		{
			return (char *)pEntry->Content->Long.Value;
		}
		else return NULL;
	}

	DllExport unsigned int GetContentLength(CalendarEntry *pEntry)
	{
		if (pEntry->Content)
		{
			return pEntry->Content->Long.Length;
		}
		return 0;
	}

	DllExport unsigned int GetContentData(CalendarEntry *pEntry, PVOID dst, unsigned int len)
	{
		if (!pEntry->Content) return 0;
		unsigned int rlen = min(len, pEntry->Content->Long.Length);
		memcpy(dst, pEntry->Content->Long.Value, rlen);
		return rlen;
	}

	DllExport char *GetContentType(CalendarEntry *pEntry)
	{
		if (pEntry->ContentType)
			return (char *)pEntry->ContentType->Long.Value;
		else
			return NULL;
	}

	DllExport int GetAttachmentCount(CalendarEntry *pEntry)
	{
		if (!pEntry->Attachments) return 0;
		return pEntry->Attachments->Count;
	}

	DllExport Attachment *GetFirstAttachment(CalendarEntry *pEntry)
	{
		if (!pEntry->Attachments)
		{
			return NULL;
		}
		return pEntry->Attachments->Attachment;
	}

	DllExport Attachment *GetNextAttachment(Attachment *a)
	{
		a++;
		return a;
	}

	DllExport char *GetAttachmentName(Attachment *a)
	{
		return (char *)a->Name->Short.Value;
	}

	DllExport unsigned int GetAttachmentBlobLength(Attachment *a)
	{
		return a->Blob->Length;
	}

	DllExport HRESULT GetAttachmentBlob(Attachment *a, void *p, unsigned int len)
	{
		HRESULT hr = S_FALSE;

		if (!(len < a->Blob->Length))
		{
			memcpy(p, a->Blob->Data, a->Blob->Length);
			hr = S_OK;
		}

		return hr;
	}
}
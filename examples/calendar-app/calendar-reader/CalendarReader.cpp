/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* CalendarReader.cpp : Entry point for the sample application
* containing planted bugs used to demonstrate fuzzing effectiveness
*
*********************************************************************/

#include "stdafx.h"
#include <stdlib.h>
#include <Windows.h>
#include <stdio.h>
#include "FileLoader.h"
#include "CalendarLib.h"

/// <summary>
/// Returns true if the ContentType string is "text", false otherwise
/// </summary>
#pragma warning (disable: 4996) // Suppress compiler warning re: use of strcpy
bool IsTextContentType(HANDLE e)
{
	char ctype[8];

	if (!GetContentType(e))
	{
		return false;
	}

	char* contentType = GetContentType(e);

	/* Planted Bug #10:	String-based stack buffer overflow
	*
	* BUG DESCRIPTION:	strcpy() is used to copy a content type string into an 8 byte buffer (ctype).
	*					strcpy() does not perform boundschecking. if the string is larger than
	*					8 bytes (including terminating 0-byte), a stack buffer (ctype) will be overflow.
	*
	* BUG IMPACT:		A skilled attacker can leverage this overflow to gain arbitrary code execution.
	*
	* BUG FIX:			Perform bounds checking, and as a backup, use a string copy function that
	*					performs correct bounds checking, such as strcpy_s().
	*/

	// Toggle Bug
	if (IsBugEnabled(BUG_10))
	{
		strcpy(ctype, contentType); // Bug #10
	}
	else
	{
		// strcpy_s only prevents the overflow; will still throw an
		// invalid parameter exception without this check
		if (strlen(contentType) > sizeof(ctype))
		{
			return false;
		}
		strcpy_s(ctype, contentType);
	}

	if (strstr(ctype, "text"))
	{
		return true;
	}

	return false;
}

/// <summary>
/// Prints the content(s) of each element of the given calendar
/// </summary>
HRESULT PrintCalendar(HANDLE calhandle)
{
	printf("PRINTING CALENDAR\n");

	int entryCount = GetCalendarEntryCount(calhandle);
	printf("Entry count: %d\n", entryCount);

	HANDLE e = GetFirstCalendarEntry(calhandle);
	if (!e)
	{
		printf("No CalendarEntries found, exiting\n");
		return S_FALSE;
	}

	for (int i = 0; i < entryCount; i++)
	{
		printf("PRINTING ENTRY %d\n", i);

		HRESULT hr;
		int year, month, day;
		int hour, min, sec;

		printf("  Type: %d\n", GetCalendarEntryType(e)); // Bug #5: this function will dereference e (NULL the 2nd time)

		printf("  From: %s <%s>\n", GetContactName(GetSender(e)), GetContactEmail(GetSender(e)));

		HANDLE c = GetFirstRecipient(e);
		if (c)
		{
			printf("  To: ");
			do
			{
				printf("%s <%s>, ", GetContactName(c), GetContactEmail(c));
				c = GetNextRecipient(c);
			} while (c);

			printf("\n");
		}

		printf("  Location: %s\n", GetLocation(e));

		printf("  Subject: %s\n", GetSubject(e));

		hr = GetStartDate(e, &year, &month, &day); // Field not mandatory, so check first
		if (hr == S_OK)
		{
			printf("  StartDate: %02d/%02d/%02d\n", month, day, year);
		}

		hr = GetStartTime(e, &hour, &min, &sec);
		printf("  StartTime: %02d:%02d:%02d (%s)\n", hour, min, sec, GetTimeZone(e));

		hr = GetDuration(e, &hour, &min, &sec);
		printf("  Duration: %02d:%02d:%02d\n", hour, min, sec);

		if (GetContentType(e))
		{
			/* Planted Bug #9:	Format string injection
			*
			* BUG DESCRIPTION:	an untrusted string is passed as a format string to printf().  If an attacker
			*					includes format specifiers (e.g. %d, %s, %n, ...) in this string, they would be
			*					evaluated, which could allow reading data from the stack, reading data from
			*					pointers on the stack, and possibly writing data to pointers on the stack.
			*					(This is the format-string equivalent of a SQL injection attack.)
			*
			* BUG IMPACT:		A skilled attacker can exploit this and gain arbitrary code execution.
			*
			* BUG FIX:			Ensure no untrusted data ends up in the format string itself, or ensure that the
			*					untrusted data is passed to printf only through format specifiers in the format string
			*					(the equivalent of SQL parameterization)
			*/

			// Toggle Bug
			if (IsBugEnabled(BUG_9))
			{
				printf("  ContentType: ");
				printf(GetContentType(e)); // Bug #9:  format specifiers appearing in incoming text will be evaluated
				printf("\n");
			}
			else
			{
				printf("  ContentType: %s\n", GetContentType(e));  // Any format specifiers will not be evaluated, only treated as text
			}
		}

		if (IsTextContentType(e))
		{
			printf("  Content: %s\n", GetContent(e));
		}

		int attachmentCount = GetAttachmentCount(e);
		if (attachmentCount)
		{
			int j;
			HANDLE a = GetFirstAttachment(e);
			for (j = 0; j < attachmentCount; j++)
			{
				printf("  Attachment: %s\n", GetAttachmentName(a));
				// TODO: Print attachment name

				a = GetNextAttachment(a);
			}
		}

		e = GetNextCalendarEntry(e); // Bug #5: second time through the loop, e is NULL
	}

	return S_OK;
}

bool FileExists(const char * filePath)
{
	bool exists = false;

	FILE *fp = fopen(filePath, "rb");
	if (fp)
	{
		// file exists
		exists = true;
		fclose(fp);
	}

	return exists;
}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
extern "C" int LLVMFuzzerTestOneInput(unsigned char *data, size_t size)
{
	HANDLE calhandle = NULL;
	calhandle = ParseCalendarFileBuffer(data, size);

	if (!calhandle) {
		printf("failure parsing calendar\n");
	}
	else
	{
		PrintCalendar(calhandle);
	}

	return 0;
}
#else
/// <summary>
/// Entry point.  Call CalendarReader.exe with a path; add an optional
/// -nobugs switch after to turn off all the bugs
/// </summary>
int main(int argc, char* argv[])
{
	HANDLE calhandle = NULL;
	HRESULT hr = NULL;

	printf("------------------------------------------------------\n");
	printf("Microsoft Security Risk Detection Demo: CalendarReader\n");

	if (argc < 2 || argc > 3)
	{
		goto PRINT_USAGE_EXIT;
	}

	const char* filePath = argv[1];
	// const char* filePath = R"(D:\set\path\manually\this\way.cal)";

	if( !FileExists(filePath) )
	{
		goto PRINT_USAGE_EXIT;
	}

	DisableBug(TRYEXCEPT);

	if (argv[2]&& 0 == strcmp(argv[2], "-nobugs"))
	{
		DisableBug(1);
		DisableBug(2);
		DisableBug(3);
		DisableBug(4);
		DisableBug(5);
		DisableBug(6);
		DisableBug(7);
		DisableBug(8);
		DisableBug(9);
		DisableBug(10);
		printf("-> All planted bugs are disabled\n");
	}

	//PVOID psys = &system;
	//printf("system(): 0x%p\n\n", psys);

	calhandle = LoadCalendarFileFromPath(filePath);
	if (!calhandle)
	{
		printf("FAILURE PARSING FILE\n");
		hr = -1;
	}
	else
	{
		hr = PrintCalendar(calhandle);
	}

	// Uncomment to block exit:
	// getchar();

	return hr;

PRINT_USAGE_EXIT:
	printf("Usage: CalendarReader.exe:\n");
	printf("    [full path to calendar file]\n");
	printf("    -nobugs (optional)\n");
	return hr;
}
#endif

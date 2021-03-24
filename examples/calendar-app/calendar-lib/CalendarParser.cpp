/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* CalendarParser.cpp:  calendar file parsing routines
* containing planted bugs used to demonstrate fuzzing effectiveness
*
*********************************************************************/

#include "stdafx.h"
#include "CalendarParser.h"
#include "CalendarBuffer.h"
#include "CalendarStructures.h"
#include <stdio.h>
#include <stdlib.h>

extern "C"
{
	extern unsigned int BugBitmask;
}

/// <summary>
/// Reads the content of an integer from the buffer into an integer that's returned
/// </summary>
int ParseInt(Buffer *pBuffer)
{
	uint32_t len = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(len));
	if (len != 4) return -1;
	if (BUFFER_LEFTOVER(pBuffer) < 4)
	{
		return -1;
	}
	uint32_t r = BUFFER_GETINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(r));
	return r;
}

/// <summary>
/// Reads the content of a string from the buffer into a CalString object that's returned
/// </summary>
CalString *ParseCalString(Buffer *pBuffer, CalStringType type)
{
	// Can be narrow or wide
	
	if (type == SHORTSTRING)
	{
		if (BUFFER_LEFTOVER(pBuffer) < sizeof(uint16_t))
		{
			return NULL;
		}

		uint16_t len = BUFFER_GETUSHORT(pBuffer);
		BUFFER_ADVANCE(pBuffer, sizeof(len));

		/* Planted Bug #1:	Integer overflow via addition
		*
		* BUG DESCRIPTION:	The len variable is incremented by 1 to account for the extra null-termination
		*					byte.  Both len and totlen are 16-bit unsigned integers, the value of which 
		*					can range from 0 to 65535.  If len is 65535, adding 1 will cause
		*					it to overflow:  the result would be 65536 (0x10000), a value that doesn't fit
		*					into an unsigned 16-bit integer.  The most significant bit (1) is dropped and the
		*					remaining 16-bits are put into totlen, whose value is now 0.
		*
		*					The problem is that totlen is used to size the temporary buffer, *p, allocated to house the
		*					parsed CalString value.   In this case, *p is has length zero, and the memcopy from
		*					the input buffer into *p will overflow.

		* BUG IMPACT:		The result of the integer overflow is a heap-based buffer overflow.  If exploited, it could
		*					allow an attacker to achieve arbitrary code execution within the hosting process.
		*
		* BUG FIX:			Add a check that tests whether the result is smaller than either of the addends:
		*
		*						c = a + b;
		*						if (c < a || c < b)
		*						{
		*							// integer_overflow_occured();
		*						}
		*
		*					This works because the result of an addition integer overflow will always
		*					be smaller than the individual values -- but only if adding two values.  If you
		*					need to add more than two, you need to do this check pair-wise.
		*/

		// Increment by 1 for null-termination byte
		unsigned short totlen = len + 1; //Bug #1 integer overflow (UINT16)

		// Toggle Bug #1
		if (IsBugDisabled(BUG_1))
		{
			if (totlen < len)
			{
				return NULL;
			}
		}

		if (BUFFER_LEFTOVER(pBuffer) < len)
		{
			return NULL;
		}

		unsigned char *p = (unsigned char *)malloc(totlen); // Bug #1: alloc too short
		if (!p)
		{
			return NULL;
		}

		memcpy(p, BUFFER_GETCURRENT(pBuffer), len); // Bug #1: memory corruption
		BUFFER_ADVANCE(pBuffer, len);
		p[len] = '\0';

		CalString *pszString = CreateCalString(type);
		if (!pszString)
		{
			free(p);
			return NULL;
		}

		pszString->Short.Length = len;
		pszString->Short.Value = p;
		return pszString;
	}
	else if (type == LONGSTRING)
	{
		if (BUFFER_LEFTOVER(pBuffer) < sizeof(uint32_t))
		{
			return NULL;
		}

		uint32_t len = BUFFER_GETUINT(pBuffer);
		BUFFER_ADVANCE(pBuffer, sizeof(len));

		// Increment by 1 for null-termination byte
		unsigned int totlen = len + 1; // Bug #1 integer overflow (UINT32)

		// Toggle Bug #6
		if (IsBugDisabled(BUG_6))
		{
			if (totlen < len)
			{
				return NULL;
			}
		}

		if (BUFFER_LEFTOVER(pBuffer) < len)
		{
			return NULL;
		}

		unsigned char *p = (unsigned char *)malloc(totlen); // Bug #1: alloc too short
		if (!p)
		{
			return NULL;
		}

		memcpy(p, BUFFER_GETCURRENT(pBuffer), len); // Bug #1: memory corruption
		BUFFER_ADVANCE(pBuffer, len);
		p[len] = '\0';

		CalString *pszString = CreateCalString(type);
		if (!pszString)
		{
			free(p);
			return NULL;
		}

		pszString->Long.Length = len;
		pszString->Long.Value = p;
		return pszString;
	}
	else
	{
		return NULL;
	}
}

/// <summary>
/// Reads the content of the Version integer from the buffer and returns it
/// </summary>
int ParseVersion(Buffer *pBuffer)
{
	return ParseInt(pBuffer);
}

/// <summary>
/// Reads the content of the EntryCount integer from the buffer and returns it
/// </summary>
int ParseEntryCount(Buffer *pBuffer)
{
	return ParseInt(pBuffer);
}

/// <summary>
/// Reads the content of an ENTRYTYPE element from the buffer into an EntryType enum that's returned
/// </summary>
enum EntryType ParseEntryType(Buffer *pBuffer)
{
	enum EntryType type = (enum EntryType) ParseInt(pBuffer);
	if (type <= NONE || type > APPOINTMENT)
	{
		return (enum EntryType) - 1;
	}
	return type;
}

/// <summary>
/// Reads the content of an nested Contact string from the buffer into an CalString struct that's returned
/// </summary>
CalString *ParseContactString(Buffer *pBuffer)
{
	return ParseCalString(pBuffer, SHORTSTRING);
}

/// <summary>
/// Reads the content of an CONTACT element from the buffer into an Contact struct that's returned
/// </summary>
#pragma warning (disable: 4703) // Suppress compiler warning re: uninitialized pointer
#pragma warning (disable: 4701) // Suppress compiler warning re: uninitialized local variable
Contact *ParseContact(Buffer *pBuffer)
{
	/* Planted Bug #2:	Uninitialized variable
	*
	* BUG DESCRIPTION:	The pointer pszString, used to temporarily store the CONTACTNAME
	*					or CONTACTEMAIL nested elements' value, is declared but not initialized.
	*					Normally, this works just fine when a Contact element in the CAL file
	*					has includes both of these values. In the case where a Contact object is
	*					included but the name and/or email is not provided, the default switch
	*					case is traversed, sending execution to the ERROR_EXIT marker.
	*
	*					When that happens, DestroyString() will be called on the pszString
	*					pointer.  Since pszString is not initialized, its value will be whatever
	*					is on the stack at the time, leading to memory corruption.
	*
	* BUG IMPACT:		The impact of uninitialized variables depends on the application.
	*					In this case, the uninitialized pointer pszString is passed to
	*					DestroyString(), which is essentially a wrapper around free(). Hence
	*					this comes down to free(\<uninitialized pointer\>). At a minimimum, this
	*					is undefined behavior and will cause memory corruption and likely result
	*					in an access violation. If she is able to influence the content of the
	*					stack at the point of the bug, a skilled attacker could potentially
	*					achieve arbitrary code execution within the hosting process.
	*
	* BUG FIX:			The fix is simply to initialize pszString to NULL.
	*/

	CalString *pszString; // Bug #2: pointer declared but not initialized

	// Toggle Bug #2
	if (IsBugDisabled(BUG_2))
	{
		pszString = NULL;
	}

	uint32_t len = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(len));
	if (BUFFER_LEFTOVER(pBuffer) < len)
	{
		return NULL;
	}

	Contact *pContact = CreateContact();
	if (!pContact)
	{
		return NULL;
	}

	while (len >= 3)
	{
		char contactElementType = BUFFER_GETCHAR(pBuffer);
		BUFFER_ADVANCE(pBuffer, 1);
		len -= 1;
		unsigned char *currbuf = BUFFER_GETCURRENT(pBuffer);

		if (contactElementType == CONTACTNAME)
		{
			if (pContact->Name != NULL)
			{
				goto ERROR_EXIT;
			}

			pszString = ParseContactString(pBuffer); // Bug #2: pszString is initialized
			if (!pszString)
			{
				goto ERROR_EXIT;
			}

			pContact->Name = pszString;
			pszString = NULL;
		}
		else if (contactElementType == CONTACTEMAIL)
		{
			if (pContact->Email != NULL)
			{
				goto ERROR_EXIT;
			}

			pszString = ParseContactString(pBuffer); // Bug #2: pszString is initialized
			if (!pszString)
			{
				printf("-> ERROR: Could not parse ContactString value\n");
				goto ERROR_EXIT;
			}

			pContact->Email = pszString;
			pszString = NULL;
		}
		else
		{
			uint32_t elen = BUFFER_GETUINT(pBuffer);
			BUFFER_ADVANCE(pBuffer, sizeof(elen));
			if (BUFFER_LEFTOVER(pBuffer) < elen)
			{
				goto ERROR_EXIT; // Bug #2: pszString is NOT initialized
			}

			/* Planted Bug #7:	Typo leads to hang
			*
			* BUG DESCRIPTION:	Typos made in less exercised code paths (such as error handling) but that still
			*					compile result in a significant number of bugs, many of which may result in
			*					security vulerabilities.
			*
			* BUG IMPACT:		TODO
			*
			* BUG FIX:			Fix the typo. :)
			*/

			// Toggle Bug #7
			if (IsBugDisabled(BUG_7))
			{
				BUFFER_ADVANCE(pBuffer, elen);
			}
			else
			{
				BUFFER_ADVANCE(pBuffer, len);  // Bug #7:  typo!  Should be elen, not len
			}
		}

		// Adjust len
		ptrdiff_t diff = BUFFER_GETCURRENT(pBuffer) - currbuf;
		if (IsBugDisabled(BUG_7))
		{
			if ((uint32_t)diff > len)
			{
				goto ERROR_EXIT;
			}
		}
		len -= diff;
	}

	// Ensure both Contact is valid:  Name and Email are defined
	if (pContact->Name == NULL || pContact->Email == NULL)
	{
		printf("ERROR: Contact must have both valid Name and Email");
		goto ERROR_EXIT;
	}

	return pContact;

ERROR_EXIT:
	DestroyCalString(pszString);	// Bug #2: free uninitialized pszString pointer
	DestroyContact(pContact);
	return NULL;
}

/// <summary>
/// Reads the content of an TIME element from the buffer into an CalTime struct that's returned
/// </summary>
CalTime *ParseTime(Buffer *pBuffer)
{
	uint32_t len = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(len));
	if (BUFFER_LEFTOVER(pBuffer) < len)
	{
		return NULL;
	}
	if (len != 3 * sizeof(unsigned int))
	{
		return NULL;
	}

	CalTime *pTime = CreateCalTime();
	if (!pTime)
	{
		return NULL;
	}

	pTime->Hour = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(unsigned int));
	pTime->Minute = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(unsigned int));
	pTime->Second = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(unsigned int));

	return pTime;
}

/// <summary>
/// Reads the content of an BLOB element from the buffer into an Blob struct that's returned
/// </summary>
Blob *ParseBlob(Buffer *pBuffer)
{
	if (BUFFER_LEFTOVER(pBuffer) < 4)
	{
		return NULL;
	}
	uint32_t len = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(len));
	if (BUFFER_LEFTOVER(pBuffer) < len)
	{
		return NULL;
	}

	Blob *pBlob = CreateBlob();
	if (!pBlob)
	{
		return NULL;
	}

	pBlob->Data = malloc(len);
	if (!pBlob->Data)
	{
		goto ERROR_EXIT;
	}

	pBlob->Length = len;
	memcpy(pBlob->Data, BUFFER_GETCURRENT(pBuffer), len);
	BUFFER_ADVANCE(pBuffer, len);

	return pBlob;

ERROR_EXIT:
	DestroyBlob(pBlob);
	return NULL;
}

/// <summary>
/// Reads the content of an STARTDATE element from the buffer into an CalDate struct that's returned
/// </summary>
CalDate *ParseDate(Buffer *pBuffer)
{
	uint32_t len = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(len));
	if (BUFFER_LEFTOVER(pBuffer) < len)
	{
		return NULL;
	}
	if (len != 3 * sizeof(unsigned int))
	{
		return NULL;
	}

	CalDate *pDate = CreateCalDate();
	if (!pDate)
	{
		return NULL;
	}

	pDate->Year = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(unsigned int));
	pDate->Month = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(unsigned int));
	pDate->Day = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(unsigned int));

	return pDate;
}

/// <summary>
/// Reads the content of one or more ATTACHMENT elements from the buffer into
/// an Attachments object that's returned
/// </summary>
Attachments *ParseAttachments(Buffer *pBuffer)
{
	CalString *pszBlobName = NULL;
	Blob *pBlob = NULL;

	uint32_t attachmentCount = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(attachmentCount));

	Attachments *pAttachments = CreateAttachments();
	if (!pAttachments)
	{
		return NULL;
	}

	/* Planted Bug #3:  Integer overflow via multiplication
	*
	* BUG DESCRIPTION:	attachmentCount is multiplied with sizeof(Attachment), essentially turning
	*					an element count into a byte count. the result of this multiplication is stored
	*					in totlen.  Both attachmentCount and totlen are unsigned int (unsigned 32 bits).
	*					sizeof() result type is of type size_t (size_t is implementation specific. as per
	*					the C99 standard it's an integer of at least 16 bits. Realistically it's an unsigned
	*					32-bit integer in 32-bit programs and an unsigned 64bit integer in 64bit programs).
	*					Assuming 32-bit, the multiplication comes down to uint32 a = uint32_b * uint32_c;
	*					because all 3 variables are 32bit, they can hold a value of 0 to 4294967295. if the
	*					result of the multiplication is larger than 4294967295, it will be too large to store
	*					in totlen. only the bottom 32bits of the result are maintained and stored in totlen.
	*
	* BUG IMPACT:		totlen is used to allocate a buffer to copy data into. if totlen overflowed the
	*					allocation will be too short. The copy after the allocation will then copy too much
	*					data into the allocated buffer. The result is a heap based buffer overflow. If properly
	*					exploited, it will allow an attack to gain arbitrary code execution within the process
	*					that this code runs in.
	*
	* BUG FIX:			Fixing multiplication interger overlows is different from fixing addition interger
	*					overflow (see above), because the multiplication integer overflowed result can still be
	*					larger than either of the individual variables. In order to fix multiplication overflow
	*					uint32_a * uint32_b you have to check if uint32_a >  4294967295 / uint32_b. if that's true
	*					then you know integer overflow will occur.
	*/

	unsigned int totlen = attachmentCount * sizeof(Attachment); // Bug #3: Integer overflow via multiplication

	// Toggle Bug #3
	if (IsBugDisabled(BUG_3))
	{
		if (attachmentCount > UINT_MAX / sizeof(Attachment))
		{
			goto ERROR_EXIT;
		}
	}

	pAttachments->Attachment = (Attachment *)calloc(1, totlen);
	if (!pAttachments->Attachment)
	{
		goto ERROR_EXIT;
	}

	pAttachments->Count = attachmentCount;
	Attachment *currentAttachment = pAttachments->Attachment;

	for (unsigned int i = 0; i < attachmentCount; i++, currentAttachment++)
	{
		// Parse and place content in local variables
		
		pszBlobName = ParseCalString(pBuffer, SHORTSTRING);
		if (!pszBlobName)
		{
			goto ERROR_EXIT;
		}

		pBlob = ParseBlob(pBuffer);
		if (!pBlob)
		{
			printf("-> ERROR: Could not parse Blob value\n");
			goto ERROR_EXIT;
		}

		currentAttachment->Blob = pBlob;		// Bug #3: memory corruption in copy loop
		currentAttachment->Name = pszBlobName;	// Bug #3: memory corruption in copy loop

		/* Planted Bug #4:	Double free
		*
		* BUG DESCRIPTION:	While parsing ATTACHMENT elements in ParseAttachments(), there is a loop that iterates through
		*					each;  the locally-scoped pointers pszBlobName and pBlob are assigned to currentAttachment->Name
		*					and currentAttachment->Blob, respectively.
		*					
		*					However, if there's an error condition that causes execution to proceed to the ERROR_EXIT label,
		*					such as if ParseCalString() returns NULL, then the error handler at ERROR_EXIT will free pBlob
		*					and its attachment pAttachment.
		*
		*					Since pAttachment contains the pBlob pointer as well, pBlob will get freed twice.
		*
		* BUG IMPACT:		A skilled attacker will be able to leverage this bug to gain arbitrary
		*					code execution. Exploitation will depend on the heap allocation
		*					implementation and algorithms used.
		*
		* BUG FIX:			To fix the bug, it's necessary to set both pBlob and pszBlobName to NULL to
		*					logically avoid the double free.  A word of caution, however:  at the point pBlob
		*					is assigned to currentAttachment->Blob and pszBlobName is assigned to
		*					currentAttachment->Name, they both 'own' the target values in the sense that
		*					the execution context of each referent is impacted by the those values.  Our
		*					fix works, but it's useful to trace the origin of the data that	pBlob and pszBlobName
		*					to ensure the fix of setting to NULL does not cause unintended side effects.
		*/

		// Toggle Bug #4
		if (IsBugDisabled(BUG_4))
		{
			pBlob = NULL;
			pszBlobName = NULL;
		}
	}

	return pAttachments;

ERROR_EXIT:
	DestroyCalString(pszBlobName);
	DestroyBlob(pBlob);
	DestroyAttachments(pAttachments); // Bug #4: will free embedded pBlob object that was just freed
	return NULL;
}

/// <summary>
/// Reads the content of an STRUCTBLOB element from the buffer into a StructuredBlob struct that's returned
/// </summary>
StructuredBlob *ParseStructuredBlob(Buffer *pBuffer)
{
	StructuredBlob *pUnknown = NULL;
	uint32_t totlen = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(totlen));
	if (BUFFER_LEFTOVER(pBuffer) < totlen)
	{
		return NULL;
	}

	if (totlen < 4)
	{
		return NULL;
	}
	uint32_t elementLength = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(elementLength));

	if (totlen - 4 < elementLength)
	{
		return NULL;
	}

	/* Planted Bug #8:	Unchecked use of tainted data, resulting in division by zero
	*
	* BUG DESCRIPTION:	An untrusted value is used as a divisor. if the value is 0, then a division
	*					by zero occurs.
	*
	* BUG IMPACT:		The result is a division by zero error that can be triggered by an attacker,
	*					resulting in an unhandled exception and potential crash.  The impact depends
	*					on the application. If this code is running as part of a service,
	*					then an attacker will be able to crash the service.
	*
	* BUG FIX:			Add a check to ensure the divisor is not 0.
	*/

	// Toggle Bug #8
	if (IsBugDisabled(BUG_8))
	{
		if (!elementLength)
		{
			return NULL;
		}
	}

	uint32_t elementCount = (totlen - 4) / elementLength;	// Bug #8: will crash if elementLength == 0

	pUnknown = CreateStructuredBlob();
	if (!pUnknown)
	{
		goto ERROR_EXIT;
	}

	pUnknown->SegmentLength = elementLength;
	pUnknown->SegmentCount = elementCount;
	pUnknown->TotalLength = elementLength * elementCount;
	pUnknown->Data = calloc(elementCount, elementLength);
	if (!pUnknown->Data)
	{
		goto ERROR_EXIT;
	}

	memcpy(pUnknown->Data, BUFFER_GETCURRENT(pBuffer), elementLength * elementCount);
	BUFFER_ADVANCE(pBuffer, (totlen - 4));

	return pUnknown;

ERROR_EXIT:
	DestroyStructuredBlob(pUnknown);
	return NULL;
}

/// <summary>
/// Advances the reading position in the buffer ahead of the current element
/// </summary>
int SkipElement(Buffer *pBuffer)
{
	uint32_t len = BUFFER_GETUINT(pBuffer);
	BUFFER_ADVANCE(pBuffer, sizeof(len));
	if (BUFFER_LEFTOVER(pBuffer) < len)
	{
		return -1;
	}
	BUFFER_ADVANCE(pBuffer, len);
	return 0;
}

/// <summary>
/// Returns true if all mandatory elements are present in the CalendarEntry, false otherwise
/// </summary>
bool IsValidEntry(CalendarEntry *pEntry)
{
	bool ret = true;
	
	if (!pEntry)
	{
		printf("Invalid CalendarEntry: Corruption\n");
		ret = false;
	}
	else if (pEntry->EntryType == 0)
	{
		printf("Invalid CalendarEntry: EntryType is 0\n");
		ret = false;
	}
	else if (pEntry->Sender == NULL)
	{
		printf("Invalid CalendarEntry: Sender is NULL\n");
		ret = false;
	}
	else if (pEntry->StartTime == NULL)
	{
		printf("Invalid CalendarEntry: StartTime is NULL\n");
		ret = false;
	}
	else if (pEntry->TimeZone == NULL)
	{
		printf("Invalid CalendarEntry: TimeZone is NULL\n");
		ret = false;
	}
	else if (pEntry->Duration == NULL)
	{
		printf("Invalid CalendarEntry: Duration is NULL\n");
		ret = false;
	}
	// TODO: if we make this mandatory, update calendar-writer
	//else if (pEntry->StartDate == NULL)
	//{
	//	printf("Invalid CalendarEntry: Sender is NULL");
	//	return -1;
	//}

	return ret;
}

/// <summary>
/// The main parsing method; contains a loop that iterates through
/// all the elements present in the incoming buffered CAL file data
/// </summary>
Calendar *ParseInput(unsigned char *in, size_t len)
{
	int version = 0;
	int entryCount = 0;					// From the file
	int entryCountCurrent = 0;			// Running total
	bool isValidpCurrentEntry = false;	// used to signal if the pCurrentEntry pointer is ready to be used
	bool hasEndElement = false;
	unsigned short elementCount = 0;

	Calendar *pCalendar = NULL;
	CalendarEntry *pCurrentEntry = NULL; // Bug #6: initial pointer to current CalendarEntry is NULL

	Buffer *pBuffer = CreateBuffer(in, len);
	if (!pBuffer)
	{
		return NULL;
	}

	// This is the main parse loop:  it will cycle through
	// the buffer, identifying individual elements

	while (BUFFER_LEFTOVER(pBuffer) >= 5) // Size of smallest element
	{
		enum EntryType entryType = NONE;
		Contact *pContact = NULL;
		CalString *pszString = NULL;
		CalTime *pTime = NULL;
		CalDate *pDate = NULL;
		Attachments *pAttachments = NULL;
		StructuredBlob *pStructBlob = NULL;

		char elementType = BUFFER_GETCHAR(pBuffer);
		BUFFER_ADVANCE(pBuffer, 1);

		// Print the element ordinal and type; content will follow
		printf("-> Parse E#%d-> [Type:%#04x]: ", ++elementCount, elementType);

		// Normally a switch statement would be used here instead of a
		// series of conditionals.  For demonstration purposes, however,
		// we've opted to use conditionals to ensure each element's type
		// byte is explicitly tested

		if (elementType == VERSION) // 0x00
		{
			if (elementCount != 1)
			{
				printf("E#1 must be VERSION (0x00), exiting\n");
				goto ERROR_EXIT;
			}
			
			version = ParseVersion(pBuffer);
			printf("VERSION=%d\n", version);
		}

		else if (elementType == ENTRYCOUNT) // 0x01
		{
			if (elementCount != 2)
			{
				printf("-> Parse ERROR: E#2 must be ENTRYCOUNT (0x01), exiting\n");
				goto ERROR_EXIT;
			}

			entryCount = ParseEntryCount(pBuffer); // Bug #5: entryCount is recorded without validation
			if (entryCount < 0)
			{
				printf("\n-> ERROR: Could not parse ENTRYCOUNT element\n");
				goto ERROR_EXIT;
			}

			printf("ENTRYCOUNT=%d\n", entryCount);
		}

		else if (elementType == NEWENTRY) // 0x02
		{
			if (!isValidpCurrentEntry)
			{
				if (entryCount == 0 || version != 1) // currently only support version one
				{
					printf("-> ERROR: Version must be 1\n");
					goto ERROR_EXIT;
				}

				// Create a calendar object to store data we retrieve from the buffer
				pCalendar = CreateCalendar(version, entryCount);
				if (!pCalendar)
				{
					printf("-> ERROR: Could not create Calendar\n");
					goto ERROR_EXIT;
				}

				pCurrentEntry = CreateCalendarEntry();	// Bug #6: where pCurrentEntry should get initialized
				if (!pCurrentEntry)
				{
					printf("-> ERROR: Could not create CalendarEntry pCurrentEntry\n");
					goto ERROR_EXIT;
				}

				pCalendar->Entry = pCurrentEntry;
				isValidpCurrentEntry = true;
			}
			else
			{
				// Add second and subsequent entries
				CalendarEntry *pNextEntry;
				if (!IsValidEntry(pCurrentEntry))
				{
					printf("-> ERROR: Invalid CalendarEntry\n");
					goto ERROR_EXIT;
				}

				pNextEntry = CreateCalendarEntry();
				if (!pNextEntry)
				{
					printf("-> ERROR: Could not create CalendarEntry pNextEntry\n");
					goto ERROR_EXIT;
				}

				pCurrentEntry->NextEntry = pNextEntry;
				pNextEntry->PreviousEntry = pCurrentEntry;
				pCurrentEntry = pNextEntry;
			}

			if (-1 == SkipElement(pBuffer))
			{
				printf("-> ERROR: Could not skip element\n");
				goto ERROR_EXIT;
			}

			// Toggle Bug #5
			if (IsBugDisabled(BUG_5))
			{
				entryCountCurrent++; // See "case END:" below for bug details
			}

			printf("NEWENTRY\n");
		}

		else if (elementType == ENTRYTYPE) // 0x03
		{
			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			if (pCurrentEntry->EntryType != 0)
			{
				printf("-> ERROR: ENTRYTYPE element must be unique in the entry\n");
				goto ERROR_EXIT;
			}

			entryType = ParseEntryType(pBuffer);
			if (entryType == (enum EntryType) - 1)
			{
				printf("\n-> ERROR: Invalid ENTRYTYPE value\n");
				goto ERROR_EXIT;
			}

			pCurrentEntry->EntryType = entryType;
			printf("ENTRYTYPE=%d\n", entryType);
		}

		else if (elementType == SENDER) // 0x04
		{
			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			if (pCurrentEntry->Sender)
			{
				printf("-> ERROR: SENDER element must be unique in the entry\n");
				goto ERROR_EXIT; // only one sender
			}

			pContact = ParseContact(pBuffer);
			if (!pContact)
			{
				printf("\n-> ERROR: Could not parse CONTACT element\n");
				goto ERROR_EXIT;
			}

			pCurrentEntry->Sender = pContact;
			printf
			(
				"SENDER (type:%d,type: %d)\n",
				pCurrentEntry->Sender->Name->StringType,
				pCurrentEntry->Sender->Email->StringType
			);
		}

		else if (elementType == RECIPIENT) // 0x05
		{
			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			pContact = ParseContact(pBuffer);
			if (!pContact)
			{
				printf("\n-> ERROR: could not parse RECIPIENT element\n");
				goto ERROR_EXIT;
			}

			if (!pCurrentEntry->Recipient)
			{
				pCurrentEntry->Recipient = pContact;
			}
			else
			{
				Contact *tempSender = pCurrentEntry->Recipient;
				while (tempSender->NextContact)
				{
					tempSender = tempSender->NextContact;
				}
				tempSender->NextContact = pContact;
			}

			printf
			(
				"RECIPIENT (type:%d,type: %d)\n",
				pCurrentEntry->Recipient->Name->StringType,
				pCurrentEntry->Recipient->Email->StringType
			);
		}

		else if (elementType == LOCATION) // 0x06
		{
			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			if (pCurrentEntry->Location)
			{
				printf("-> ERROR: LOCATION element must be unique in the entry\n");
				goto ERROR_EXIT;
			}

			pszString = ParseCalString(pBuffer, LONGSTRING);
			if (!pszString)
			{
				printf("\n-> ERROR: Could not parse CalString value\n");
				goto ERROR_EXIT;
			}

			pCurrentEntry->Location = pszString;

			printf("LOCATION=%s\n", pCurrentEntry->Location->StringType == LONGSTRING
				? pCurrentEntry->Location->Long.Value
				: pCurrentEntry->Location->Short.Value);
		}

		else if (elementType == STARTTIME) // 0x07
		{
			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			if (pCurrentEntry->StartTime)
			{
				printf("-> ERROR: STARTTIME element must be unique in the entry\n");
				goto ERROR_EXIT;
			}

			pTime = ParseTime(pBuffer);
			if (!pTime)
			{
				printf("\n-> ERROR: Could not parse STARTTIME element\n");
				goto ERROR_EXIT;
			}

			if (pTime->Hour > 24 || pTime->Minute > 60 || pTime->Second > 60)
			{
				printf("-> ERROR: Invalid STARTTIME values\n");
				DestroyCalTime(pTime);
				goto ERROR_EXIT;
			}

			pCurrentEntry->StartTime = pTime;

			printf
			(
				"STARTTIME=%d,%d,%d\n",
				pCurrentEntry->StartTime->Hour,
				pCurrentEntry->StartTime->Minute,
				pCurrentEntry->StartTime->Second
			);
		}

		else if (elementType == TIMEZONE) // 0x08
		{
			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			if (pCurrentEntry->TimeZone)
			{
				printf("-> ERROR: TIMEZONE element must be unique in the entry\n");
				goto ERROR_EXIT;
			}

			// list of timezones (TZ string. e.g. "EST", "europe/berlin", ...)
			pszString = ParseCalString(pBuffer, SHORTSTRING);
			if (!pszString)
			{
				printf("\n-> ERROR: Could not parse CalString object\n");
				goto ERROR_EXIT;
			}

			pCurrentEntry->TimeZone = pszString;

			printf("TIMEZONE=%s\n", pCurrentEntry->TimeZone->StringType == LONGSTRING
				? pCurrentEntry->TimeZone->Long.Value
				: pCurrentEntry->TimeZone->Short.Value);
		}

		else if (elementType == DURATION) // 0x09
		{
			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			if (pCurrentEntry->Duration)
			{
				printf("-> ERROR: DURATION element must be unique in the entry\n");
				goto ERROR_EXIT;
			}

			pTime = ParseTime(pBuffer);
			if (!pTime)
			{
				printf("\n-> ERROR: Could not parse TIME element\n");
				goto ERROR_EXIT;
			}

			pCurrentEntry->Duration = pTime;

			printf("DURATION=%d,%d,%d\n",
				pCurrentEntry->Duration->Hour,
				pCurrentEntry->Duration->Minute,
				pCurrentEntry->Duration->Second);
		}

		else if (elementType == STARTDATE) // 0x0A
		{
			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			if (pCurrentEntry->StartDate)
			{
				printf("-> ERROR: STARTDATE element must be unique in the entry\n");
				goto ERROR_EXIT;
			}

			pDate = ParseDate(pBuffer);
			if (!pDate)
			{
				printf("\n-> ERROR: Could not create DATE object\n");
				goto ERROR_EXIT;
			}

			pCurrentEntry->StartDate = pDate;
			printf("STARTDATE=%d,%d,%d\n",
				pCurrentEntry->StartDate->Year,
				pCurrentEntry->StartDate->Month,
				pCurrentEntry->StartDate->Day);
		}

		else if (elementType == SUBJECT) // 0x0B
		{
			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			if (pCurrentEntry->Subject)
			{
				printf("-> ERROR: SUBJECT element must be unique in the entry\n");
				goto ERROR_EXIT;
			}

			pszString = ParseCalString(pBuffer, LONGSTRING);
			if (!pszString)
			{
				printf("\n-> ERROR: Could not parse CalString value\n");
				goto ERROR_EXIT;
			}

			pCurrentEntry->Subject = pszString;

			printf("SUBJECT=%s\n", pCurrentEntry->Subject->StringType == LONGSTRING
				? pCurrentEntry->Subject->Long.Value
				: pCurrentEntry->Subject->Short.Value);
		}

		else if (elementType == CONTENT) // 0x0C
		{
			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			if (pCurrentEntry->Content)
			{
				printf("-> ERROR: CONTENT element must be unique in the entry\n");
				goto ERROR_EXIT;
			}

			pszString = ParseCalString(pBuffer, LONGSTRING);
			if (!pszString)
			{
				printf("\n-> ERROR: Could not parse CalString value\n");
				goto ERROR_EXIT;
			}

			pCurrentEntry->Content = pszString;

			printf("CONTENT=%s\n", pCurrentEntry->Content->StringType == LONGSTRING
				? pCurrentEntry->Content->Long.Value
				: pCurrentEntry->Content->Short.Value);
		}

		else if (elementType == CONTENTTYPE) // 0x0F
		{
			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			if (pCurrentEntry->ContentType)
			{
				printf("-> ERROR: CONTENTTYPE element must be unique in the entry\n");
				goto ERROR_EXIT;
			}

			pszString = ParseCalString(pBuffer, LONGSTRING);
			if (!pszString)
			{
				printf("\n-> ERROR: Could not parse CalString value\n");
				goto ERROR_EXIT;
			}

			pCurrentEntry->ContentType = pszString;

			printf("CONTENTTYPE=%s\n", pCurrentEntry->ContentType->StringType == LONGSTRING
				? pCurrentEntry->ContentType->Long.Value
				: pCurrentEntry->ContentType->Short.Value);
		}

		else if (elementType == ATTACHMENT) // 0x0D
		{
			/* Planted Bug #6:	NULL pointer dereference
			*
			* BUG DESCRIPTION:	A NULL pointer dereference occurs when a pointer is initialized to NULL
			*					and is then dereferenced without first being assigned.
			*
			* BUG IMPACT:		In most situations (as is the case here) a NULL pointer dereference will lead
			*					to a crash, since the address NULL isn't mapped in the address space, and the CPU
			*					doesn't know what to do with it.  The impact depends on the context in which this
			*					code is used; if this were a service, an attacker could leverage this NULL pointer
			*					dereference to cause a Denial of Service attack (DoS).
			*
			* BUG FIX:			In this case the isValidpCurrentEntry integer is used to signal if the CurrentEntry pointer
			*					is ready to be used.  Simply adding a check to see if FirstEntry is nonzero  will
			*					fix the problem.
			*/

			// Toggle Bug #6
			if (IsBugDisabled(BUG_6))
			{
				if (!isValidpCurrentEntry)
				{
					printf("-> ERROR: pCurrentEntry not instantiated\n");
					goto ERROR_EXIT;
				}
			}

			if (pCurrentEntry->Attachments) // Bug #6: pCurrentEntry is NULL
			{
				printf("-> ERROR: ATTACHMENT element must be unique in the entry\n");
				goto ERROR_EXIT;
			}

			pAttachments = ParseAttachments(pBuffer);
			if (!pAttachments)
			{
				printf("\n-> ERROR: Could not parse ATTACHMENT element\n");
				goto ERROR_EXIT;
			}

			pCurrentEntry->Attachments = pAttachments;
			printf("ATTACHMENT (count: %d)\n", pCurrentEntry->Attachments->Count);
		}

		else if (elementType == STRUCTBLOB) // 0x11
		{
			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			if (pCurrentEntry->StructuredBlob)
			{
				printf("-> ERROR: STRUCTBLOB element must be unique in the entry\n");
				goto ERROR_EXIT;
			}

			pStructBlob = ParseStructuredBlob(pBuffer);
			if (!pStructBlob)
			{
				printf("\n-> ERROR: Could not parse STRUCTBLOB element\n");
				goto ERROR_EXIT;
			}
			pCurrentEntry->StructuredBlob = pStructBlob;
			printf("STRUCTBLOB (Length:%d)\n", pCurrentEntry->StructuredBlob->TotalLength);
		}

		else if (elementType == END) // 0x0E
		{
			hasEndElement = true;

			/* Planted Bug #5:	Unvalidated length field
			*
			* BUG DESCRIPTION:	We're at the end of the file (END element).  EntryCount had been read from
			*					the file and presented to the caller, but is never actually verified. The provided
			*					calendar file could lie, and the current code will simply pass it on to the caller.
			*					The caller assumes that this count is valid.
			*
			* BUG IMPACT:		The impact of this issue depends on what the caller does with EntryCount. While the
			*					specific impact depends on the caller, it's really the responsibility of this to
			*					to validate EntryCount.
			*
			* BUG FIX:			Keep a running count of every entry seen (see above). Then, at the end see if our
			*					running count matches the EntryCount.
			*/

			// Toggle Bug #5
			if (IsBugDisabled(BUG_5))
			{
				if (entryCount != entryCountCurrent)
				{
					printf("-> ERROR: ENTRYCOUNT value does match file contents\n");
					goto ERROR_EXIT;
				}
			}

			BUFFER_ADVANCE(pBuffer, BUFFER_LEFTOVER(pBuffer));
			printf("END\n");
		}

		else
		{
			// Ignore elements whose type is undefined

			if (!isValidpCurrentEntry)
			{
				printf("-> ERROR: pCurrentEntry not instantiated\n");
				goto ERROR_EXIT;
			}

			if (-1 == SkipElement(pBuffer))
			{
				printf("-> ERROR: Could not skip element\n");
				goto ERROR_EXIT;
			}

			printf("Unrecognized element type, skipped\n");
		}
	}

	if(!hasEndElement)
	{
		printf("-> ERROR: file must terminate with a unique END element\n");
		goto ERROR_EXIT;
	}

	// Ensure all the mandatory elements are present in the file
	if (!IsValidEntry(pCurrentEntry))
	{
		goto ERROR_EXIT;
	}

	DestroyBuffer(pBuffer);
	printf("\n");

	return pCalendar;

ERROR_EXIT:
	DestroyBuffer(pBuffer);
	DestroyCalendar(pCalendar);
	pCalendar = NULL;
	return NULL;
}

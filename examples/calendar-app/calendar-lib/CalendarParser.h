/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* CalendarParser.h:  enums used by the calendar file format
* and parser code
*
*********************************************************************/

enum ElementType
{
	VERSION,        // 0x00		Mandatory; must be first element
	ENTRYCOUNT,     // 0x01		Mandatory; must be second element
	NEWENTRY,       // 0x02		Mandatory
	ENTRYTYPE,      // 0x03		Mandatory
	SENDER,         // 0x04		Mandatory
	RECIPIENT,      // 0x05
	LOCATION,		// 0x06
	STARTTIME,      // 0x07		Mandatory
	TIMEZONE,       // 0x08		Mandatory
	DURATION,       // 0x09		Mandatory
	STARTDATE,      // 0x0A
	SUBJECT,        // 0x0B
	CONTENT,        // 0x0C
	ATTACHMENT,     // 0x0D
	END,            // 0x0E		Mandatory; must be last element
	CONTENTTYPE,    // 0x0F
	TEMP,           // 0x10
	STRUCTBLOB      // 0x11
};

enum ContactType
{
	CONTACTNAME,
	CONTACTEMAIL
};

enum EntryType
{
	NONE,
	MEETING,
	APPOINTMENT
};
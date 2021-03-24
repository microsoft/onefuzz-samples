/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* include file for standard system include files, or project specific
* include files that are used frequently, but are changed infrequently
*
*********************************************************************/

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>

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

//extern "C" unsigned int BugBitmask = ~0;

#define EnableBug(x)  (unsigned int)BugBitmask |= (1 << x)
#define DisableBug(x) (unsigned int)BugBitmask &= (~(1 << x))
#define IsBugEnabled(x) (unsigned int)BugBitmask & (1 << x)
#define IsBugDisabled(x) !((unsigned int)BugBitmask & (1 << x))

// TODO: reference additional headers your program requires here

/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* CalendarBuffer.cpp:  contains Calendar buffer management functions
*
*********************************************************************/

#include "stdafx.h"
#include "CalendarBuffer.h"
#include <stdlib.h>

void DestroyBuffer(Buffer *b)
{
	free(b);
	return;
}

Buffer *CreateBuffer(unsigned char *in, size_t len)
{
	Buffer *b = (Buffer *)calloc(1, sizeof(Buffer));
	if (!b)
	{
		return b;
	}

	b->begin = in;
	b->end = in + len;
	b->current = b->begin;
	b->len = len;
	b->leftover = b->len;
	return b;
}
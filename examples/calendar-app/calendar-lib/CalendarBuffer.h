/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* CalendarBuffer.h:  contains the Calendar buffer management structure
* and macros
*
*********************************************************************/

#include <stdint.h>

typedef struct _Buffer
{
	unsigned char *begin;
	unsigned char *end;
	size_t len;
	unsigned char *current;
	size_t leftover;
} Buffer;

#define BUFFER_ADVANCE(b, l) { \
	b->leftover -= l; b->current += l; \
}

#define BUFFER_LEFTOVER(b) b->leftover
#define BUFFER_GETCHAR(b) *(b->current)

#define BUFFER_GETUCHAR(b) *(uint8_t *)b->current
#define BUFFER_GETINT(b) *(int32_t *)b->current
#define BUFFER_GETUINT(b) *(uint32_t *)b->current
#define BUFFER_GETSHORT(b) *(int16_t *)b->current
#define BUFFER_GETUSHORT(b) *(uint16_t *)b->current

#define BUFFER_GETCURRENT(b) b->current

void DestroyBuffer(Buffer *b);

Buffer *CreateBuffer(unsigned char *in, size_t len);
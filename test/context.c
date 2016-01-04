#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <assert.h>

#include <cn-cbor/cn-cbor.h>

#ifdef USE_CONTEXT
#include "context.h"

typedef unsigned char byte;

typedef struct {
	cn_cbor_context context;
	byte * pFirst;
} MyContext;

typedef struct _MyItem {
	struct _MyItem *	pNext;
	size_t		size;
	byte        pad[4];
	byte        data[4];
} MyItem;


bool CheckMemory(MyContext * pContext)
{
	MyItem * p;
	int i;

	//  Walk memory and check every block

	for (p =  (MyItem *) pContext->pFirst; p != NULL; p = p->pNext) {
		if (p->pad[0] == (byte) 0xab) {
			//  Block has been freed
			for (i = 0; i < p->size + 8; i++) {
				if (p->pad[i] != (byte) 0xab) {
					fprintf(stderr, "Freed block is modified");
					assert(false);
				}
			}
		}
		else if (p->pad[0] == (byte) 0xef) {
			for (i = 0; i < 4; i++) {
				if ((p->pad[i] != (byte) 0xef) || (p->pad[i + 4 + p->size] != (byte) 0xef)) {
					fprintf(stderr, "Curent block was overrun");
					assert(false);
				}
			}
		}
		else {
			fprintf(stderr, "Incorrect pad value");
			assert(false);
		}
	}

	return true;
}

void * MyCalloc(size_t count, size_t size, void * context)
{
	MyItem * pb = (MyItem *) malloc(sizeof(MyItem) + count*size);
	MyContext * myContext = (MyContext *)context;

	CheckMemory(myContext);

	memset(pb, 0xef, sizeof(MyItem) + count*size);
	memset(&pb->data, 0, count*size);

	pb->pNext = (struct _MyItem *) myContext->pFirst;
	myContext->pFirst = (byte *) pb;
	pb->size = count*size;

    return &pb->data;
}

void MyFree(void * ptr, void * context)
{
	MyItem * pb = (MyItem *) ((byte *) ptr - sizeof(MyItem) + 4);
	MyContext * myContext = (MyContext *)context;

	CheckMemory(myContext);

	memset(&pb->pad, 0xab, pb->size + 8);
}


cn_cbor_context * CreateContext()
{
	MyContext * p = malloc(sizeof(MyContext));

	p->context.calloc_func = MyCalloc;
	p->context.free_func = MyFree;
	p->context.context = p;
	p->pFirst = NULL;

	return &p->context;
}

void FreeContext(cn_cbor_context* pContext)
{
	MyContext * myContext = (MyContext *)pContext;
	MyItem * pItem;
	MyItem * pItem2;

	CheckMemory(myContext);

	for (pItem = (MyItem *) myContext->pFirst; pItem != NULL;  pItem = pItem2) {
		pItem2 = pItem->pNext;
		free(pItem);
	}

	free(myContext);

	return;
}

#endif // USE_CONTEXT
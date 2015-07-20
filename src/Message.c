#include <stdlib.h>

#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto.h"

bool _COSE_Free(COSE * p)
{
	COSE_FREE(p, &p->m_allocContext);
	return true;
}


#pragma once

#include "SignerInfo.hpp"

struct COSE_CounterSign {
	COSE_SignerInfo m_signer;
	COSE_CounterSign *m_next;
};

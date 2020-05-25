#pragma once

#include "SignerInfo.hpp"

class COSE_CounterSign {
   public:
	COSE_SignerInfo m_signer{};
	COSE_CounterSign *m_next{nullptr};
};

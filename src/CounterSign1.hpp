#pragma once

#include "CounterSign.hpp"

class COSE_CounterSign1 {
   public:
	COSE_SignerInfo m_signer{};
	COSE_CounterSign1 *m_next{nullptr};
};

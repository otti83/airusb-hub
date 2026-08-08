#include "CreditController.h"

namespace airusb {

Status CreditController::acquire(std::uint32_t bytes) noexcept
{
    if (!wouldFit(bytes)) return Status::NoResources;
    _urbsInUse  += 1;
    _bytesInUse += bytes;
    return Status::Ok;
}

bool CreditController::release(std::uint32_t bytes) noexcept
{
    // Underflow here is an accounting bug in our own code, not peer misbehaviour.
    // Refusing to wrap is what keeps a single mistake from permanently closing the
    // window: an unsigned wrap would make bytesInUse enormous and the endpoint
    // would never send again.
    if (_urbsInUse == 0 || _bytesInUse < bytes) return false;
    _urbsInUse  -= 1;
    _bytesInUse -= bytes;
    return true;
}

void CreditController::recordOverrun(std::uint32_t requestedBytes) noexcept
{
    ++_overruns;
    if (static_cast<std::uint64_t>(requestedBytes) > 2ull * _grant.bytes) _grossOverrun = true;
    if (_urbsInUse > 2u * _grant.urbs) _grossOverrun = true;
}

bool CreditController::overrunIsFatal() const noexcept
{
    return _grossOverrun || _overruns >= 3;
}

} // namespace airusb

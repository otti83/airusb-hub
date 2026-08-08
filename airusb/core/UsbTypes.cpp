#include "UsbTypes.h"

namespace airusb {

const char* speedName(Speed s) noexcept
{
    switch (s) {
        case Speed::None:          return "none";
        case Speed::Full:          return "Full(12M)";
        case Speed::Low:           return "Low(1.5M)";
        case Speed::High:          return "High(480M)";
        case Speed::Super:         return "Super(5G)";
        case Speed::SuperPlus:     return "SuperPlus(10G)";
        case Speed::SuperPlusBy2:  return "SuperPlusBy2(20G)";
        case Speed::Other:         return "other";
    }
    return "?";
}

} // namespace airusb

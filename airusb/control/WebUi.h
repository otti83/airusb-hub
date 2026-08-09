// AirUSB Hub — the window, compiled in.
//
// One page, no assets, no filesystem. The daemon serves it from memory, which
// means there is no install path to get wrong, no directory to traverse, and no
// version skew between a binary and the files beside it. Copy the executable to
// a machine and the UI is on it.
//
// It is stored as several chunks rather than one literal because MSVC has
// historically capped a single string literal well below the size of a real
// page, and discovering that from a compiler nobody on this machine can run is
// exactly the kind of avoidable surprise the Windows work has already paid for
// twice. Concatenating at runtime costs one allocation at startup.

#ifndef AIRUSB_CONTROL_WEBUI_H
#define AIRUSB_CONTROL_WEBUI_H

#include <string>

namespace airusb::control {

/// The whole page: HTML, CSS and script in one document.
std::string indexHtml();

} // namespace airusb::control

#endif // AIRUSB_CONTROL_WEBUI_H

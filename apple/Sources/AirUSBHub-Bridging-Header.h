//  Exposes the Objective-C core to Swift.
//
//  IOKit is a C API with manual retain/release and CF bridging. Doing it from
//  Swift means Unmanaged and takeRetainedValue at every call site; doing it once
//  in Objective-C means Swift sees plain objects.
#import "Core/AirUSBCore.h"

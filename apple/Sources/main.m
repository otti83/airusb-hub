//
//  AirUSB Hub — entitlement probe, in the shape a shipping product signs in.
//
//  WHY THIS TARGET EXISTS
//
//  Two jobs, both of which need an Xcode project rather than a bare clang binary:
//
//  1. Register the App ID. The Developer portal's "Capability Requests" tab lives
//     INSIDE an App ID, so it does not exist until one does — and the only
//     non-manual way to create one is Xcode's automatic signing, which calls the
//     Developer API on your behalf. `codesign` on a loose binary never contacts
//     the portal, which is why poc/p0-probe never produced an App ID.
//
//  2. Answer, definitively and at any time, whether
//     com.apple.developer.usb.host-controller-interface has been granted yet.
//     Before the grant this is expected to fail; after it, it is expected to
//     succeed. Nothing else in the tree can tell the two apart, because the
//     failure of an unentitled process is a SIGKILL from AMFI, not an error code.
//
//  READING THE RESULT
//
//    exit 0   the controller was created. THE ENTITLEMENT IS LIVE. P2.9 unblocks.
//    exit 2   kIOReturnNotOpen (0xE00002CD) — ran, was refused. No entitlement in
//             the signature, which is the correct state before the grant.
//    SIGKILL  AMFI killed the process. It claimed a restricted entitlement that
//             the provisioning profile does not authorise. Also expected before
//             the grant, IF the entitlement has been added to the plist early.
//
//  The distinction between "exit 2" and "SIGKILL" is the whole diagnostic: it
//  separates "we did not ask" from "we asked and were refused", and P0 measured
//  both. See docs/P0_MACOS_FEASIBILITY.md.
//
//  SAFETY
//
//  One unpowered root port, destroyed within a few seconds. The capabilities
//  blob is Apple's own example from IOUSBHostControllerInterface.h, used verbatim
//  so that any failure is attributable to authorisation rather than to a
//  malformed payload — which would raise IOUSBHostCIExceptionTypeCapabilitiesInvalid
//  and look like a very different problem.
//

#import <Foundation/Foundation.h>
#import <IOKit/IOReturn.h>
#import <IOUSBHost/IOUSBHostControllerInterface.h>
#import <IOUSBHost/IOUSBHostDefinitions.h>

// Apple's example controller capabilities: 1 root port, command timeout
// threshold 2^1 = 2 s, connection latency 2^2 = 4 ms.
static const IOUSBHostCIMessage kControllerCapabilities = {
    .control = (IOUSBHostCIMessageTypeControllerCapabilities << IOUSBHostCIMessageControlTypePhase)
             | IOUSBHostCIMessageControlNoResponse
             | IOUSBHostCIMessageControlValid
             | (1 << IOUSBHostCICapabilitiesMessageControlPortCountPhase),
    .data0   = (1 << IOUSBHostCICapabilitiesMessageData0CommandTimeoutThresholdPhase)
             | (2 << IOUSBHostCICapabilitiesMessageData0ConnectionLatencyPhase),
    .data1   = 0
};

// Apple's example port capabilities: port 1, ACPI connector type 0 (Type-A),
// 907 mA expressed in 8 mA units.
static const IOUSBHostCIMessage kPortCapabilities = {
    .control = (IOUSBHostCIMessageTypePortCapabilities << IOUSBHostCIMessageControlTypePhase)
             | IOUSBHostCIMessageControlNoResponse
             | IOUSBHostCIMessageControlValid
             | (1 << IOUSBHostCIPortCapabilitiesMessageControlPortNumberPhase)
             | (0 << IOUSBHostCIPortCapabilitiesMessageControlConnectorTypePhase),
    .data0   = ((907 / 8) << IOUSBHostCIPortCapabilitiesMessageData0MaxPowerPhase),
    .data1   = 0
};

static void logLine(const char *tag, NSString *fmt, ...) NS_FORMAT_FUNCTION(2, 3);
static void logLine(const char *tag, NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *m = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    fprintf(stdout, "@@AIRUSB_%s@@ %s\n", tag, m.UTF8String);
    fflush(stdout);
}

/// Reads the entitlements actually present in our own signature, so the report
/// distinguishes "we never claimed it" from "we claimed it and were refused".
static void reportOwnEntitlements(void)
{
    NSBundle *bundle = [NSBundle mainBundle];
    logLine("PROBE", @"bundle=%@ path=%@",
            bundle.bundleIdentifier ?: @"(none)", bundle.bundlePath ?: @"(none)");

    // On macOS the profile lives at Contents/embedded.provisionprofile, NOT in
    // Contents/Resources — so -pathForResource:ofType: never finds it and would
    // report ABSENT for a bundle that has one. (It did, on the first run.)
    NSString *profile = [bundle.bundlePath
                            stringByAppendingPathComponent:@"Contents/embedded.provisionprofile"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:profile]) {
        NSData *raw = [NSData dataWithContentsOfFile:profile];
        logLine("PROBE", @"embedded.provisionprofile: PRESENT (%lu bytes)",
                (unsigned long)raw.length);

        // The profile is CMS-signed; the plist is embedded in it. Rather than
        // decode it here, report whether the entitlement string occurs at all —
        // which is the only question that matters and needs no parser.
        NSData *needle = [@"com.apple.developer.usb.host-controller-interface"
                             dataUsingEncoding:NSUTF8StringEncoding];
        const BOOL granted = [raw rangeOfData:needle
                                      options:0
                                        range:NSMakeRange(0, raw.length)].location != NSNotFound;
        logLine("PROBE", @"profile authorises host-controller-interface: %@",
                granted ? @"YES" : @"NO");
    } else {
        // Without a profile, a restricted entitlement cannot be authorised at
        // all — AMFI has nothing to check the claim against.
        logLine("PROBE", @"embedded.provisionprofile: ABSENT — no restricted "
                          "entitlement can be authorised without one");
    }
}

int main(int argc, const char *argv[])
{
    (void)argc; (void)argv;

    @autoreleasepool {
        logLine("PROBE", @"AirUSB Hub entitlement probe");
        reportOwnEntitlements();

        NSMutableData *caps = [NSMutableData dataWithBytes:&kControllerCapabilities
                                                    length:sizeof(IOUSBHostCIMessage)];
        [caps appendBytes:&kPortCapabilities length:sizeof(IOUSBHostCIMessage)];

        NSError *err = nil;
        IOUSBHostControllerInterface *controller = nil;

        // Wrapped for the same reason every IOUSBHost call in this project is:
        // Apple's error path can raise NSInvalidArgumentException instead of
        // returning an NSError. Measured twice — on openWithOptions: during P1,
        // and on descriptorWithType: during the P2.8 gate run.
        @try {
            controller = [[IOUSBHostControllerInterface alloc]
                             initWithCapabilities:caps
                                            queue:nil
                                  interruptRateHz:1000
                                            error:&err
                                   // Signatures taken from the header's own
                                   // typedefs: the command message arrives BY
                                   // VALUE, and the doorbell count is uint32_t,
                                   // not NSUInteger.
                                   commandHandler:^(IOUSBHostControllerInterface *ci,
                                                    IOUSBHostCIMessage command) {
                                       (void)ci; (void)command;
                                   }
                                  doorbellHandler:^(IOUSBHostControllerInterface *ci,
                                                    IOUSBHostCIDoorbell *doorbells,
                                                    uint32_t count) {
                                       (void)ci; (void)doorbells; (void)count;
                                   }
                                  interestHandler:nil];
        } @catch (NSException *ex) {
            logLine("ERROR", @"RESULT=THREW %@: %@", ex.name, ex.reason);
            return 3;
        }

        if (controller) {
            logLine("PROBE", @"RESULT=GRANTED — IOUSBHostControllerInterface was created.");
            logLine("PROBE", @"uuid=%@", controller.uuid);
            logLine("PROBE", @"The entitlement is live on this signature. P2.9 is unblocked.");
            [controller destroy];
            return 0;
        }

        const unsigned code = (unsigned)(err ? err.code : 0);
        logLine("ERROR", @"RESULT=REFUSED 0x%08X (%@)", code, err.domain ?: @"?");

        if (code == (unsigned)kIOReturnNotOpen) {
            logLine("ERROR", @"0xE00002CD kIOReturnNotOpen — the process ran and was "
                              "refused. This is the EXPECTED state before Apple grants "
                              "com.apple.developer.usb.host-controller-interface.");
        } else if (code == (unsigned)kIOReturnNotPermitted) {
            logLine("ERROR", @"0xE00002E2 kIOReturnNotPermitted — a policy check refused "
                              "it, which is a different failure from a missing entitlement.");
        }
        logLine("ERROR", @"If this process had CLAIMED the entitlement without a profile "
                          "authorising it, AMFI would have killed it instead of letting "
                          "it reach this line.");
        return 2;
    }
}

//
//  p0_probe.m — AirUSB Hub Phase 0 feasibility probe
//
//  PURPOSE (diagnostic only — this file is not product code):
//    Determine empirically whether a third-party, Developer-ID-signable process on this
//    Mac can instantiate a user-mode USB host controller via the PUBLIC macOS SDK class
//    IOUSBHostControllerInterface, and exactly how the system rejects it when it cannot.
//
//    IOUSBHostControllerInterface.h states:
//      "IOUSBHostControllerInterface enables a process to instantiate a USB host controller
//       to provide access to remote USB devices or create synthetic USB devices.
//       The entitlement com.apple.developer.usb.host-controller-interface is required to
//       use this class."
//
//    The capabilities structures below are Apple's own example from that header, used
//    verbatim so that a failure is attributable to authorization, not to a malformed
//    capabilities payload (which would raise IOUSBHostCIExceptionTypeCapabilitiesInvalid).
//
//  SAFETY:
//    The controller is created with a single unpowered root port and is destroyed within
//    a few seconds. The kernel's command-timeout threshold is set to 2s; we service
//    controller/port commands via the SDK state machines so the kernel driver never times
//    out, then tear down cleanly via -destroy.
//

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOUSBHost/IOUSBHostControllerInterface.h>
#import <IOUSBHost/IOUSBHostCIControllerStateMachine.h>
#import <IOUSBHost/IOUSBHostCIPortStateMachine.h>
#import <IOUSBHost/IOUSBHostDefinitions.h>

// Apple's example controller capabilities (IOUSBHostControllerInterface.h):
//   1 root port, command timeout threshold 2^1 = 2 seconds, connection latency 2^2 = 4 ms.
static const IOUSBHostCIMessage kControllerCapabilities = {
    .control = (IOUSBHostCIMessageTypeControllerCapabilities << IOUSBHostCIMessageControlTypePhase)
             | IOUSBHostCIMessageControlNoResponse
             | IOUSBHostCIMessageControlValid
             | (1 << IOUSBHostCICapabilitiesMessageControlPortCountPhase),
    .data0   = (1 << IOUSBHostCICapabilitiesMessageData0CommandTimeoutThresholdPhase)
             | (2 << IOUSBHostCICapabilitiesMessageData0ConnectionLatencyPhase),
    .data1   = 0
};

// Apple's example port capabilities: port 1, ACPI connector type 0 (Type-A), 907mA in 8mA units.
static const IOUSBHostCIMessage kPortCapabilities = {
    .control = (IOUSBHostCIMessageTypePortCapabilities << IOUSBHostCIMessageControlTypePhase)
             | IOUSBHostCIMessageControlNoResponse
             | IOUSBHostCIMessageControlValid
             | (1 << IOUSBHostCIPortCapabilitiesMessageControlPortNumberPhase)
             | (0 << IOUSBHostCIPortCapabilitiesMessageControlConnectorTypePhase),
    .data0   = ((907 / 8) << IOUSBHostCIPortCapabilitiesMessageData0MaxPowerPhase),
    .data1   = 0
};

static void log_line(const char *tag, NSString *fmt, ...) NS_FORMAT_FUNCTION(2, 3);
static void log_line(const char *tag, NSString *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    fprintf(stdout, "@@AIRUSB_%s@@ %s\n", tag, msg.UTF8String);
    fflush(stdout);
}

static void interest_handler(void *refCon, io_service_t service, uint32_t messageType, void *messageArgument)
{
    (void)refCon; (void)service;
    log_line("PROBE", @"interest: messageType=0x%08x arg=%p", messageType, messageArgument);
}

int main(int argc, const char *argv[])
{
    (void)argc; (void)argv;
    @autoreleasepool
    {
        log_line("PROBE", @"pid=%d euid=%d", getpid(), geteuid());

        NSMutableData *capabilities = [[NSMutableData alloc] initWithBytes:&kControllerCapabilities
                                                                    length:sizeof(IOUSBHostCIMessage)];
        [capabilities appendBytes:&kPortCapabilities length:sizeof(IOUSBHostCIMessage)];

        __block IOUSBHostControllerInterface *controller = nil;

        IOUSBHostControllerInterfaceCommandHandler commandHandler =
        ^(IOUSBHostControllerInterface *ctrl, IOUSBHostCIMessage command)
        {
            uint32_t type = (command.control & IOUSBHostCIMessageControlType) >> IOUSBHostCIMessageControlTypePhase;
            log_line("PROBE", @"command: %@", [ctrl descriptionForMessage:&command]);

            NSError *err = nil;
            if (type >= IOUSBHostCIMessageTypeControllerPowerOn && type <= IOUSBHostCIMessageTypeControllerFrameNumber)
            {
                IOUSBHostCIControllerStateMachine *sm = ctrl.controllerStateMachine;
                if ([sm inspectCommand:&command error:&err])
                {
                    [sm respondToCommand:&command status:IOUSBHostCIMessageStatusSuccess error:&err];
                }
            }
            else if (type >= IOUSBHostCIMessageTypePortPowerOn && type <= IOUSBHostCIMessageTypePortStatus)
            {
                IOUSBHostCIPortStateMachine *sm = [ctrl getPortStateMachineForCommand:&command error:&err];
                if (sm && [sm inspectCommand:&command error:&err])
                {
                    // Reflect power state so the kernel's port model stays consistent.
                    if (type == IOUSBHostCIMessageTypePortPowerOn)  { sm.powered = YES; }
                    if (type == IOUSBHostCIMessageTypePortPowerOff) { sm.powered = NO;  }
                    [sm respondToCommand:&command status:IOUSBHostCIMessageStatusSuccess error:&err];
                }
            }
            if (err) { log_line("ERROR", @"command handling: %@", err); }
        };

        IOUSBHostControllerInterfaceDoorbellHandler doorbellHandler =
        ^(IOUSBHostControllerInterface *ctrl, IOUSBHostCIDoorbell *doorbells, uint32_t count)
        {
            (void)ctrl;
            log_line("PROBE", @"doorbell: count=%u first=0x%08x", count, count ? doorbells[0] : 0);
        };

        NSError *error = nil;
        log_line("PROBE", @"calling initWithCapabilities:queue:interruptRateHz:error:...");

        controller = [[IOUSBHostControllerInterface alloc] initWithCapabilities:capabilities
                                                                         queue:nil
                                                               interruptRateHz:1000
                                                                         error:&error
                                                                commandHandler:commandHandler
                                                               doorbellHandler:doorbellHandler
                                                               interestHandler:interest_handler];

        if (controller == nil)
        {
            log_line("ERROR", @"RESULT=DENIED controller=nil error=%@ (domain=%@ code=%ld)",
                     error, error.domain, (long)error.code);
            return 2;
        }

        if (error != nil && error.code != KERN_SUCCESS)
        {
            log_line("ERROR", @"RESULT=DENIED controller=%p but error code=%ld (0x%lx) domain=%@",
                     controller, (long)error.code, (long)error.code, error.domain);
            [controller destroy];
            return 3;
        }

        log_line("PROBE", @"RESULT=CREATED uuid=%@ queue=%p", controller.uuid, controller.queue);
        log_line("PROBE", @"a user-mode USB host controller now exists; holding 3s to observe kernel commands");

        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            dispatch_semaphore_signal(done);
        });
        dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);

        log_line("PROBE", @"destroying controller");
        [controller destroy];
        log_line("PROBE", @"RESULT=OK clean teardown");
        return 0;
    }
}

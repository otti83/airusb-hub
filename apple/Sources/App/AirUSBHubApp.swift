import SwiftUI

@main
struct AirUSBHubApp: App {
    @StateObject private var model = DeviceListModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 720, minHeight: 460)
        }
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .newItem) { }   // there is no "new document"
        }
    }
}

/// The app's state.
///
/// Deliberately thin: it holds what the IORegistry says and what the entitlement
/// probe found, and nothing else. Anything that changes a device's state belongs
/// behind the root daemon, not in a view model.
@MainActor
final class DeviceListModel: ObservableObject {
    @Published private(set) var devices: [AirUSBDeviceInfo] = []
    @Published private(set) var entitlement: AirUSBEntitlementReport?
    @Published var lastError: String?
    @Published var busyDeviceId: String?

    private let watcher = AirUSBDeviceWatcher()

    init() {
        watcher.onChange = { [weak self] in
            Task { @MainActor in self?.refresh() }
        }
        watcher.start()
        refresh()
    }

    deinit { watcher.stop() }

    func refresh() {
        devices = watcher.currentDevices()
    }

    /// Run on demand rather than at launch. Creating a virtual USB controller is
    /// cheap but it is not nothing, and doing it unprompted every time the app
    /// opens would be a surprising thing for a GUI to do.
    func checkImporterReadiness() {
        entitlement = AirUSBEntitlementProbe.run()
    }

    func eject(_ device: AirUSBDeviceInfo) {
        busyDeviceId = device.stableId
        lastError = nil
        AirUSBEjector.ejectDevice(device) { [weak self] (error: Error?) in
            Task { @MainActor in
                guard let self else { return }
                self.busyDeviceId = nil
                if let error {
                    // Show the recovery suggestion too — DiskArbitration often
                    // names the process holding the volume, which is the only
                    // part the user can act on.
                    let suggestion = (error as NSError)
                        .localizedRecoverySuggestion.map { "\n\($0)" } ?? ""
                    self.lastError = error.localizedDescription + suggestion
                }
                self.refresh()
            }
        }
    }
}

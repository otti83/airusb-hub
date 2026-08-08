import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: DeviceListModel
    @State private var selection: String?

    var body: some View {
        NavigationSplitView {
            DeviceList(selection: $selection)
                .navigationSplitViewColumnWidth(min: 260, ideal: 300)
        } detail: {
            if let device = model.devices.first(where: { $0.stableId == selection }) {
                DeviceDetail(device: device)
            } else {
                EmptyDetail()
            }
        }
        .alert("Could not eject",
               isPresented: Binding(get: { model.lastError != nil },
                                    set: { if !$0 { model.lastError = nil } })) {
            Button("OK", role: .cancel) { model.lastError = nil }
        } message: {
            Text(model.lastError ?? "")
        }
    }
}

// MARK: - list

private struct DeviceList: View {
    @EnvironmentObject private var model: DeviceListModel
    @Binding var selection: String?

    var body: some View {
        List(selection: $selection) {
            Section("Attached to this Mac") {
                if model.devices.isEmpty {
                    Text("No USB devices")
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 6)
                } else {
                    ForEach(model.devices, id: \.stableId) { d in
                        DeviceRow(device: d).tag(d.stableId)
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            ImporterStatusBar()
        }
    }
}

private struct DeviceRow: View {
    let device: AirUSBDeviceInfo

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: device.hasStorage ? "externaldrive" : "cable.connector")
                .font(.title3)
                .foregroundStyle(device.isBootDisk ? Color.secondary : Color.accentColor)
                .frame(width: 22)

            VStack(alignment: .leading, spacing: 2) {
                Text(device.productName).lineLimit(1)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 2)
    }

    private var subtitle: String {
        if device.isBootDisk { return "Startup disk" }
        if !device.mountPoints.isEmpty {
            return device.mountPoints
                .map { ($0 as NSString).lastPathComponent }
                .joined(separator: ", ")
        }
        return device.hasStorage ? "Not mounted" : device.identifierText
    }
}

// MARK: - detail

private struct DeviceDetail: View {
    @EnvironmentObject private var model: DeviceListModel
    let device: AirUSBDeviceInfo

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header

                if device.isBootDisk {
                    Callout(kind: .warning,
                            title: "This is the startup disk",
                            message: "AirUSB Hub will never unmount or share the disk "
                                   + "macOS is running from.")
                }

                if device.speedPropertiesDisagree {
                    // Worth surfacing rather than hiding: the IORegistry publishes
                    // two speed properties with different enumerations, and this
                    // is what a misreading looks like from the outside.
                    Callout(kind: .warning,
                            title: "This Mac reports two different link speeds",
                            message: "The negotiated speed and the measured link rate "
                                   + "disagree. The device may be in a hub or a cable "
                                   + "that cannot carry its full speed.")
                }

                Facts(device: device)

                if device.hasStorage { volumes }

                actions
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: device.hasStorage ? "externaldrive" : "cable.connector")
                .font(.system(size: 40))
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 3) {
                Text(device.productName).font(.title2).bold()
                if !device.vendorName.isEmpty {
                    Text(device.vendorName).foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
    }

    private var volumes: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Volumes").font(.headline)
            if device.mountPoints.isEmpty {
                Text("Nothing is mounted from this device.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(device.mountPoints, id: \.self) { path in
                    HStack(spacing: 8) {
                        Image(systemName: "folder")
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 1) {
                            Text((path as NSString).lastPathComponent)
                            Text(path).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    private var actions: some View {
        VStack(alignment: .leading, spacing: 12) {
            Divider()
            HStack(spacing: 12) {
                Button {
                    model.eject(device)
                } label: {
                    if model.busyDeviceId == device.stableId {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Eject", systemImage: "eject")
                    }
                }
                .disabled(device.mountPoints.isEmpty
                          || device.isBootDisk
                          || model.busyDeviceId != nil)

                Button {
                    // Intentionally not wired to anything yet. See the note.
                } label: {
                    Label("Share on my network", systemImage: "antenna.radiowaves.left.and.right")
                }
                .disabled(true)
            }

            // An honest disabled button beats a button that appears to work.
            // Sharing needs the root helper, which is not installed by this app
            // yet — the exporter currently runs from the command line.
            Text("Sharing is not available from this window yet. The sharing "
               + "engine works and is driven from the command line; connecting it "
               + "to this app is the next step.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct Facts: View {
    let device: AirUSBDeviceInfo

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
            row("Speed", device.speedText)
            if device.linkSpeedBitsPerSecond > 0 {
                row("Link rate", String(format: "%.1f Gb/s",
                                        device.linkSpeedBitsPerSecond / 1e9))
            }
            row("Identifier", device.identifierText)
            row("Port", String(format: "0x%08X", device.locationId))
            if device.hasStorage {
                row("Devices", device.bsdNames.joined(separator: ", "))
            }
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            Text(value).textSelection(.enabled).monospacedDigit()
        }
    }
}

private struct EmptyDetail: View {
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "cable.connector.horizontal")
                .font(.system(size: 48))
                .foregroundStyle(.tertiary)
            Text("Select a device").font(.title3).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - importer status

private struct ImporterStatusBar: View {
    @EnvironmentObject private var model: DeviceListModel
    @State private var showDetail = false

    var body: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 8) {
                Image(systemName: icon).foregroundStyle(tint)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Receiving devices").font(.caption).foregroundStyle(.secondary)
                    Text(model.entitlement?.summary ?? "Not checked")
                        .font(.caption).bold().lineLimit(1)
                }
                Spacer()
                Button(model.entitlement == nil ? "Check" : "Recheck") {
                    model.checkImporterReadiness()
                    showDetail = true
                }
                .controlSize(.small)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
        .popover(isPresented: $showDetail, arrowEdge: .top) {
            if let e = model.entitlement {
                VStack(alignment: .leading, spacing: 10) {
                    Text(e.summary).font(.headline)
                    Text(e.detail)
                        .fixedSize(horizontal: false, vertical: true)
                    if e.state != .granted {
                        Divider()
                        Text("Provisioning profile: "
                             + (e.profilePresent ? "present" : "absent")
                             + "\nAuthorises USB host controller: "
                             + (e.profileAuthorisesEntitlement ? "yes" : "no"))
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(16)
                .frame(width: 380)
            }
        }
    }

    private var icon: String {
        switch model.entitlement?.state {
        case .granted: return "checkmark.circle.fill"
        case .none:    return "questionmark.circle"
        default:       return "exclamationmark.triangle.fill"
        }
    }

    private var tint: Color {
        switch model.entitlement?.state {
        case .granted: return .green
        case .none:    return .secondary
        default:       return .orange
        }
    }
}

// MARK: - bits

private struct Callout: View {
    enum Kind { case warning, info }
    let kind: Kind
    let title: String
    /// Named `message`, not `body` — `body` is SwiftUI's own requirement on View
    /// and a stored property of that name silently shadows it.
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: kind == .warning
                  ? "exclamationmark.triangle.fill" : "info.circle.fill")
                .foregroundStyle(kind == .warning ? Color.orange : Color.accentColor)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).bold()
                Text(message)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }
}

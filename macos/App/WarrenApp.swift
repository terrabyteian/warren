// The menu-bar app: sign in with the organization URL, then connect. It
// installs the packet tunnel system extension and starts the tunnel
// through NetworkExtension; the extension runs the client core's engine.
// Until the app is signed (docs/macos.md), the command-line client is how
// warren runs on a Mac; this app builds unsigned so it is ready.

import AppKit
@preconcurrency import NetworkExtension
import SwiftUI
import SystemExtensions

let tunnelBundleID = "dev.warren.client.tunnel"

@main
struct WarrenApp: App {
    @StateObject private var model = Model()

    var body: some Scene {
        MenuBarExtra("warren", systemImage: model.connected ? "lock.shield.fill" : "lock.shield") {
            MenuView(model: model)
        }
        .menuBarExtraStyle(.window)
    }
}

/// What the menu shows, and the actions behind it.
@MainActor
final class Model: NSObject, ObservableObject, OSSystemExtensionRequestDelegate {
    @Published var org = ""
    @Published var user = ""
    @Published var device = ""
    @Published var apps: [String] = []
    @Published var message: String?
    @Published var connected = false
    @Published var busy = false

    private var manager: NETunnelProviderManager?

    override init() {
        super.init()
        refresh()
        NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main
        ) { [weak self] note in
            let status = (note.object as? NEVPNConnection)?.status
            Task { @MainActor in self?.connected = status == .connected }
        }
    }

    /// Reloads the saved sign-in.
    func refresh() {
        let status = WarrenCore.status(home: SharedState.directory)
        if status.error != nil {
            user = ""
            device = ""
            apps = []
            return
        }
        org = (status.object["org"] as? String) ?? org
        user = (status.object["user"] as? String) ?? ""
        let state = (status.object["device_status"] as? String) ?? ""
        device = "\((status.object["device"] as? String) ?? "") (\(state))"
        apps = ((status.object["apps"] as? [[String: Any]]) ?? []).compactMap {
            $0["name"] as? String
        }
    }

    /// Signs in through the browser; the core waits for it to come back.
    func signIn() {
        let org = self.org
        busy = true
        message = "Finish signing in in your browser."
        DispatchQueue.global(qos: .userInitiated).async {
            let result = WarrenCore.login(home: SharedState.directory, org: org, fingerprint: nil) {
                url in
                DispatchQueue.main.async { NSWorkspace.shared.open(url) }
            }
            DispatchQueue.main.async {
                self.busy = false
                if let error = result.error {
                    self.message = error
                } else if let pending = result.object["pending"] as? [String: Any] {
                    self.message = pending["detail"] as? String
                } else {
                    self.message = nil
                }
                self.refresh()
            }
        }
    }

    /// Installs (or updates) the packet tunnel system extension.
    func installExtension() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: tunnelBundleID, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Saves the tunnel configuration and starts it.
    func connect() {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            Task { @MainActor in
                if let error {
                    self.message = error.localizedDescription
                    return
                }
                let manager = managers?.first ?? NETunnelProviderManager()
                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = tunnelBundleID
                proto.serverAddress = self.org
                manager.protocolConfiguration = proto
                manager.localizedDescription = "warren"
                manager.isEnabled = true
                manager.saveToPreferences { error in
                    Task { @MainActor in
                        if let error {
                            self.message = error.localizedDescription
                            return
                        }
                        do {
                            try manager.connection.startVPNTunnel()
                            self.manager = manager
                        } catch {
                            self.message = error.localizedDescription
                        }
                    }
                }
            }
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            self.message = "Allow warren's system extension in System Settings."
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in self.message = nil }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in self.message = error.localizedDescription }
    }
}

struct MenuView: View {
    @ObservedObject var model: Model

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("warren").font(.headline)
            if model.user.isEmpty {
                TextField("https://warren.example.com", text: $model.org)
                    .textFieldStyle(.roundedBorder)
                Button("Sign in") { model.signIn() }
                    .disabled(model.org.isEmpty || model.busy)
            } else {
                Text(model.user)
                Text("Device \(model.device)").font(.caption).foregroundStyle(.secondary)
                ForEach(model.apps, id: \.self) { Text($0).font(.caption) }
                HStack {
                    if model.connected {
                        Button("Disconnect") { model.disconnect() }
                    } else {
                        Button("Connect") { model.connect() }
                    }
                    Button("Install extension") { model.installExtension() }
                }
            }
            if let message = model.message {
                Text(message).font(.caption).foregroundStyle(.orange)
            }
            Divider()
            HStack {
                Text("core \(WarrenCore.version)").font(.caption2).foregroundStyle(.secondary)
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }
        }
        .padding()
        .frame(width: 300)
    }
}

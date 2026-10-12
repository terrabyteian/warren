// The client core, reached through its C interface
// (crates/warren-ffi/include/warren.h). The app and the packet tunnel
// provider both link it; neither implements any protocol itself.

import CWarren
import Foundation

/// Where the app and the tunnel provider share the client's state: the
/// app group container once the app is signed with its entitlements, the
/// command-line client's directory until then.
enum SharedState {
    static let appGroup = "group.dev.warren.client"

    static var directory: URL {
        if let group = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroup)
        {
            return group.appendingPathComponent("warren", isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/warren", isDirectory: true)
    }
}

/// A JSON object the core returned, or its error.
struct CoreResult {
    let object: [String: Any]

    var error: String? { object["error"] as? String }

    init(taking pointer: UnsafeMutablePointer<CChar>?) {
        guard let pointer else {
            object = ["error": "the client core returned nothing"]
            return
        }
        defer { warren_string_free(pointer) }
        let data = Data(String(cString: pointer).utf8)
        object =
            (try? JSONSerialization.jsonObject(with: data) as? [String: Any])
            ?? ["error": "the client core returned malformed JSON"]
    }
}

enum WarrenCore {
    static var version: String { String(cString: warren_version()) }

    /// The saved sign-in, device and apps.
    static func status(home: URL) -> CoreResult {
        CoreResult(taking: warren_status_json(home.path))
    }

    private final class OpenBox {
        let open: (URL) -> Void
        init(_ open: @escaping (URL) -> Void) { self.open = open }
    }

    /// Signs in through the browser and enrolls the device. Blocks until
    /// the browser comes back, so call it off the main thread.
    static func login(home: URL, org: String, fingerprint: String?, open: @escaping (URL) -> Void)
        -> CoreResult
    {
        let box = Unmanaged.passRetained(OpenBox(open))
        defer { box.release() }
        let result = warren_login(
            home.path, org, fingerprint, 300,
            { ctx, url in
                guard let ctx, let url, let target = URL(string: String(cString: url)) else {
                    return
                }
                Unmanaged<OpenBox>.fromOpaque(ctx).takeUnretainedValue().open(target)
            }, box.toOpaque())
        return CoreResult(taking: result)
    }
}

struct CoreError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

/// A running tunnel engine: packets in and out, network settings to apply,
/// and events to show.
final class WarrenTunnel {
    private var handle: OpaquePointer?
    private let deliver: (Data) -> Void
    private let apply: ([String: Any]) -> Bool
    private let event: ([String: Any]) -> Void

    init(
        home: URL,
        deliver: @escaping (Data) -> Void,
        apply: @escaping ([String: Any]) -> Bool,
        event: @escaping ([String: Any]) -> Void
    ) throws {
        self.deliver = deliver
        self.apply = apply
        self.event = event
        var error: UnsafeMutablePointer<CChar>?
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        handle = warren_tunnel_start(
            home.path, ctx,
            { ctx, packet, len in
                guard let ctx, let packet else { return }
                Unmanaged<WarrenTunnel>.fromOpaque(ctx).takeUnretainedValue()
                    .deliver(Data(bytes: packet, count: len))
            },
            { ctx, json in
                guard let ctx, let json else { return false }
                let data = Data(String(cString: json).utf8)
                guard let settings = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
                else { return false }
                return Unmanaged<WarrenTunnel>.fromOpaque(ctx).takeUnretainedValue().apply(settings)
            },
            { ctx, json in
                guard let ctx, let json else { return }
                let data = Data(String(cString: json).utf8)
                if let e = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    Unmanaged<WarrenTunnel>.fromOpaque(ctx).takeUnretainedValue().event(e)
                }
            }, &error)
        if handle == nil {
            let message = error.map { String(cString: $0) } ?? "the tunnel did not start"
            warren_string_free(error)
            throw CoreError(message: message)
        }
    }

    /// Gives the engine a packet the system routed into the tunnel.
    func send(_ packet: Data) {
        packet.withUnsafeBytes { raw in
            warren_tunnel_send(handle, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
    }

    /// The engine's state.
    var status: CoreResult { CoreResult(taking: warren_tunnel_status_json(handle)) }

    /// Closes the tunnels; callbacks stop before this returns.
    func stop() {
        warren_tunnel_stop(handle)
        handle = nil
    }

    deinit { stop() }
}

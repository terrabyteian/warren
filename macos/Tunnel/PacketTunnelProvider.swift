// The packet tunnel provider: the system extension that carries warren's
// tunnel once the app is signed. It runs the client core's engine and only
// moves packets and applies the routes the engine asks for: internal apps
// only, never a default route.

@preconcurrency import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var tunnel: WarrenTunnel?
    private let log = Logger(subsystem: "dev.warren.client.tunnel", category: "tunnel")

    override func startTunnel(
        options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let tunnel = try WarrenTunnel(
                    home: SharedState.directory,
                    deliver: { [weak self] packet in
                        self?.packetFlow.writePackets(
                            [packet], withProtocols: [Self.family(of: packet)])
                    },
                    apply: { [weak self] settings in
                        self?.apply(settings) ?? false
                    },
                    event: { [weak self] event in
                        let line = (event["event"] as? String) ?? "event"
                        self?.log.notice("\(line, privacy: .public): \(event.description, privacy: .public)")
                    })
                self.tunnel = tunnel
                self.readPackets()
                completionHandler(nil)
            } catch {
                self.log.error("\(error.localizedDescription, privacy: .public)")
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        tunnel?.stop()
        tunnel = nil
        completionHandler()
    }

    /// The protocol number `writePackets` wants for an IP packet.
    static func family(of packet: Data) -> NSNumber {
        let version = (packet.first ?? 0) >> 4
        return NSNumber(value: version == 6 ? AF_INET6 : AF_INET)
    }

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, let tunnel = self.tunnel else { return }
            for packet in packets {
                tunnel.send(packet)
            }
            self.readPackets()
        }
    }

    /// Applies the engine's settings: the device's tunnel addresses, the
    /// MTU, and routes for exactly the internal apps' ranges.
    private func apply(_ s: [String: Any]) -> Bool {
        let addresses = (s["addresses"] as? [String]) ?? []
        let routes = (s["routes"] as? [String]) ?? []
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        if let mtu = s["mtu"] as? Int {
            settings.mtu = NSNumber(value: mtu)
        }
        let v4 = addresses.filter { !$0.contains(":") }
        if !v4.isEmpty {
            let ipv4 = NEIPv4Settings(
                addresses: v4, subnetMasks: v4.map { _ in "255.255.255.255" })
            ipv4.includedRoutes = routes.compactMap(Self.ipv4Route)
            settings.ipv4Settings = ipv4
        }
        let v6 = addresses.filter { $0.contains(":") }
        if !v6.isEmpty {
            let ipv6 = NEIPv6Settings(addresses: v6, networkPrefixLengths: v6.map { _ in 128 })
            ipv6.includedRoutes = routes.compactMap(Self.ipv6Route)
            settings.ipv6Settings = ipv6
        }
        let done = DispatchSemaphore(value: 0)
        var ok = false
        setTunnelNetworkSettings(settings) { error in
            ok = error == nil
            done.signal()
        }
        done.wait()
        return ok
    }

    static func ipv4Route(_ cidr: String) -> NEIPv4Route? {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, !parts[0].contains(":"), let len = UInt32(parts[1]), len <= 32
        else { return nil }
        let mask = len == 0 ? 0 : UInt32.max << (32 - len)
        let dotted = (0..<4).map { String((mask >> (24 - 8 * $0)) & 0xff) }.joined(separator: ".")
        return NEIPv4Route(destinationAddress: String(parts[0]), subnetMask: dotted)
    }

    static func ipv6Route(_ cidr: String) -> NEIPv6Route? {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, parts[0].contains(":"), let len = Int(parts[1]), len <= 128 else {
            return nil
        }
        return NEIPv6Route(
            destinationAddress: String(parts[0]), networkPrefixLength: NSNumber(value: len))
    }
}

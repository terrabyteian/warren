// The system extension's entry point: hand control to NetworkExtension,
// which instantiates PacketTunnelProvider when the tunnel starts.

import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()

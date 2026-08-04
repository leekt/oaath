/**
 EXPERIMENTAL PREVIEW — the pairing link the web half prints as a QR code.

 `examples/phone` renders `oaath-demo://pair?relay=<url>&code=<pairing code>`
 in the terminal (QR + copyable text). Scanning it with the system camera or
 tapping it opens this app (the Demo target registers the `oaath-demo` URL
 scheme), and pasting it into the pairing-code field works too. Parsing only
 FILLS the pairing screen; pairing itself stays an explicit button, exactly
 like deciding stays an explicit Approve/Reject.

 @author taek <leekt216@gmail.com>
 */
import Foundation

public struct PairingLink: Equatable, Sendable {
    public let relayURL: String
    public let pairingCode: String

    public init(relayURL: String, pairingCode: String) {
        self.relayURL = relayURL
        self.pairingCode = pairingCode
    }
}

/// Strict parse of `oaath-demo://pair?relay=…&code=…`; anything else is nil.
/// The relay URL must itself satisfy the demo endpoint rule (http/https+host).
public func parsePairingLink(_ text: String) -> PairingLink? {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let components = URLComponents(string: trimmed),
          components.scheme?.lowercased() == "oaath-demo",
          components.host == "pair" || components.path == "pair"
    else {
        return nil
    }
    var relay: String?
    var code: String?
    var seenNames = Set<String>()
    for item in components.queryItems ?? [] {
        guard seenNames.insert(item.name).inserted else { return nil }
        switch item.name {
        case "relay": relay = item.value
        case "code": code = item.value
        default: return nil
        }
    }
    guard let relay, let code, !code.isEmpty,
          (try? DemoRelayEndpoint(baseURLText: relay)) != nil
    else {
        return nil
    }
    return PairingLink(relayURL: relay, pairingCode: code)
}

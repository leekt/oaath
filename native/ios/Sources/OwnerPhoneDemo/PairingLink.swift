/**
 EXPERIMENTAL PREVIEW — the pairing link the web half prints as a QR code.

 `examples/phone` renders `oaath-demo://pair?relay=<url>&code=<pairing code>`
 in the terminal (QR + copyable text). The in-app scanner reads it directly;
 the system Camera can also open it through the Demo target's `oaath-demo` URL
 scheme, and pasting it into the pairing-code field works too. Parsing only
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
    guard !text.isEmpty, text.utf8.count <= 2_048 else { return nil }
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let components = URLComponents(string: trimmed),
          components.scheme == "oaath-demo",
          components.host == "pair",
          components.user == nil,
          components.password == nil,
          components.port == nil,
          components.path.isEmpty,
          components.fragment == nil
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
    guard let relay, let code = code.flatMap(PairingCode.init),
          (try? DemoRelayEndpoint(baseURLText: relay)) != nil
    else {
        return nil
    }
    return PairingLink(relayURL: relay, pairingCode: code.value)
}

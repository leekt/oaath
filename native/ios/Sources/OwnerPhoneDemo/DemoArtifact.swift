/**
 EXPERIMENTAL PREVIEW — the demo's approval artifact source.

 HONEST SIGNING BOUNDARY: in this demo the phone AUTHORIZES via the relay's
 one-shot decision, and this artifact is an opaque placeholder. A real
 deployment seals owner-device material here — the on-device owner-key
 signature of the Kernel enable digest lives behind exactly this seam and is
 NOT cryptographically real in this demo (and cannot be on-chain-real yet: no
 reviewed Kernel v4 P-256/WebAuthn validator is pinned — the recorded release
 blocker). What the phone displays IS what the relay's decision authorizes.

 @author taek <leekt216@gmail.com>
 */
import Foundation

public func demoApprovalArtifact() -> String {
    // Deliberately structureless: nothing downstream may mistake it for a
    // protocol decision or a signature.
    "demo-owner-phone-approval:v1:placeholder-artifact"
}

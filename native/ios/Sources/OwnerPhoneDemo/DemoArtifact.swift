/**
 EXPERIMENTAL PREVIEW — the demo's structured-permission approval artifact.

 Permission consent authorizes through the relay's one-shot decision and seals
 no device signature. Raw and owner-signing scopes are reject-only before
 this placeholder can be requested.

 @author taek <leekt216@gmail.com>
 */
import Foundation

public func demoApprovalArtifact() -> String {
    // Deliberately structureless: nothing downstream may mistake it for a
    // protocol decision or a signature.
    "demo-owner-phone-approval:v1:placeholder-artifact"
}

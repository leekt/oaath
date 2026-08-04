/**
 EXPERIMENTAL PREVIEW — the demo's approval artifact for NON-signature scopes.

 The signing boundary is real now: a signature-request scope's approval signs
 the projected digest with the on-device owner key (`DemoOwnerKey`, Secure
 Enclave where available) and the artifact IS that signature. This placeholder
 remains only for the other scope kinds (permission-request consent, raw
 text), whose demo approvals authorize via the relay's one-shot decision and
 seal no device material.

 @author taek <leekt216@gmail.com>
 */
import Foundation

public func demoApprovalArtifact() -> String {
    // Deliberately structureless: nothing downstream may mistake it for a
    // protocol decision or a signature.
    "demo-owner-phone-approval:v1:placeholder-artifact"
}

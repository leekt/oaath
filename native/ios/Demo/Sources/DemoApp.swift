/**
 EXPERIMENTAL PREVIEW — the runnable owner-phone demo app.

 Thin @main over the package: push registration (registration only — a
 notification tap opens the consent screen and never decides anything),
 keychain credential custody, and the demo screens. Everything testable lives
 in the OwnerPhoneDemo target; this file only wires it.

 @author taek <leekt216@gmail.com>
 */
import OwnerPhone
import OwnerPhoneDemo
import SwiftUI

@main
struct OwnerPhoneDemoApp: App {
    @UIApplicationDelegateAdaptor(PushRegistrationDelegate.self) private var pushDelegate
    @StateObject private var model = DemoModel(credentials: KeychainCredentialStore())

    var body: some Scene {
        WindowGroup {
            DemoRootView(model: model)
                .task {
                    pushDelegate.onDeviceToken = { token in
                        // Pairing registers this token with the relay.
                        Task { @MainActor in model.deviceToken = token }
                    }
                    pushDelegate.onPush = { push in
                        // Opens the review only; approving stays an explicit tap.
                        Task { await model.receive(push: push) }
                    }
                }
        }
    }
}

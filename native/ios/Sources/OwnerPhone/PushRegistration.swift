/**
 EXPERIMENTAL PREVIEW — APNs registration and notification routing.

 Registers for remote notifications, hex-encodes the device token for the
 relay's device registry, and routes a tapped notification's payload through
 the closed `OwnerPhonePush` decoder. A payload that fails the closed decode
 is dropped: push delivery is never authorization, so nothing is lost — the
 request remains reachable through the authenticated channel.

 Real APNs delivery, Apple provisioning, and entitlements are deployment work
 outside this repository.

 @author taek <leekt216@gmail.com>
 */
#if canImport(UIKit)
import UIKit
import UserNotifications

@MainActor
public final class PushRegistrationDelegate: NSObject, UIApplicationDelegate,
    UNUserNotificationCenterDelegate
{
    /// Lowercase hex APNs device token, as the relay's device registry expects.
    public var onDeviceToken: (String) -> Void = { _ in }
    public var onPush: (OwnerPhonePush) -> Void = { _ in }

    public func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        Task {
            let granted = (try? await UNUserNotificationCenter.current()
                .requestAuthorization(options: [.alert, .sound])) ?? false
            if granted {
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
        if let payload = launchOptions?[.remoteNotification] as? [AnyHashable: Any],
           let push = try? OwnerPhonePush.decode(userInfo: payload)
        {
            onPush(push)
        }
        return true
    }

    public func application(
        _ application: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        onDeviceToken(deviceToken.map { String(format: "%02x", $0) }.joined())
    }

    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }

    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse
    ) async {
        if let push = try? OwnerPhonePush.decode(
            userInfo: response.notification.request.content.userInfo)
        {
            onPush(push)
        }
    }
}
#endif

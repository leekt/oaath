/**
 EXPERIMENTAL PREVIEW — OAuth-style code delivery.

 After a *decided* approval the relay releases a one-time code and the redirect
 URI the stored request registered. The phone delivers the code the OAuth way:
 one GET of `redirectUri` with `?code=<released code>` appended. A replayed
 settlement releases nothing, so there is never anything to deliver twice.

 @author taek <leekt216@gmail.com>
 */
import Foundation

public enum CodeDeliveryError: Error, Equatable, Sendable {
    case invalidRedirectUri
}

/// Builds the delivery URL, preserving any query the redirect URI already has.
public func codeDeliveryURL(redirectUri: String, code: String) throws -> URL {
    guard var components = URLComponents(string: redirectUri),
          let scheme = components.scheme?.lowercased(),
          scheme == "http" || scheme == "https",
          components.host != nil
    else {
        throw CodeDeliveryError.invalidRedirectUri
    }
    components.queryItems = (components.queryItems ?? []) + [URLQueryItem(name: "code", value: code)]
    guard let url = components.url else {
        throw CodeDeliveryError.invalidRedirectUri
    }
    return url
}

/// Performs the single delivery GET; returns the HTTP status for narration.
public func deliverCode(
    redirectUri: String,
    code: String,
    http: any DemoHTTP
) async throws -> Int {
    var request = URLRequest(url: try codeDeliveryURL(redirectUri: redirectUri, code: code))
    request.httpMethod = "GET"
    let (_, status) = try await http.send(request)
    return status
}

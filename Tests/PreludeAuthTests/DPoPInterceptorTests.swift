@testable import PreludeAuth
import XCTest

final class DPoPInterceptorTests: XCTestCase {
    // MARK: - htuURL

    func test_htuURL_stripsQueryAndFragment() throws {
        let url = try XCTUnwrap(URL(string: "https://api.example.com/v1/session/login?foo=bar#frag"))
        let request = URLRequest(url: url)

        let htu = try XCTUnwrap(DPoPInterceptor.htuURL(for: request))

        XCTAssertEqual(htu.absoluteString, "https://api.example.com/v1/session/login")
    }

    func test_htuURL_preservesPercentEncodedPath() throws {
        // Paths with encoded characters must round-trip byte-for-byte
        // so the client's htu matches the server's reconstruction.
        let request = try URLRequest(url: XCTUnwrap(URL(string: "https://api.example.com/v1/users/a%20b/sessions")))

        let htu = try XCTUnwrap(DPoPInterceptor.htuURL(for: request))

        XCTAssertEqual(htu.absoluteString, "https://api.example.com/v1/users/a%20b/sessions")
    }

    func test_htuURL_usesHostOverrideVerbatim() throws {
        var request = try URLRequest(url: XCTUnwrap(URL(string: "https://127.0.0.1:3000/v1/session/login")))
        request.setValue("sessdev.example.com", forHTTPHeaderField: HTTPHeader.host)

        let htu = try XCTUnwrap(DPoPInterceptor.htuURL(for: request))

        XCTAssertEqual(htu.absoluteString, "https://sessdev.example.com/v1/session/login")
    }

    func test_htuURL_withHostOverridePreservesPercentEncodedPath() throws {
        let url = try XCTUnwrap(URL(string: "https://127.0.0.1:3000/v1/users/a%20b/sessions?token=xyz"))
        var request = URLRequest(url: url)
        request.setValue("sessdev.example.com:443", forHTTPHeaderField: HTTPHeader.host)

        let htu = try XCTUnwrap(DPoPInterceptor.htuURL(for: request))

        XCTAssertEqual(htu.absoluteString, "https://sessdev.example.com:443/v1/users/a%20b/sessions")
    }
}

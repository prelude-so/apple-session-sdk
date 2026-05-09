import Foundation

/// Signs outgoing requests with a DPoP proof and retries once on the
/// `use_dpop_nonce` challenge. Non-JSON error bodies propagate as
/// plain HTTP errors. The keypair is created lazily on first use.
struct DPoPInterceptor: Interceptor {
    let domain: String
    let keyStore: DPoPKeyStore
    let proofBuilder: DPoPProofBuilder

    init(
        domain: String,
        keyStore: DPoPKeyStore,
        proofBuilder: DPoPProofBuilder = DefaultDPoPProofBuilder()
    ) {
        self.domain = domain
        self.keyStore = keyStore
        self.proofBuilder = proofBuilder
    }

    func intercept(
        _ request: URLRequest,
        next: SendFunction
    ) async throws -> (Data, HTTPURLResponse) {
        let key = try keyStore.getOrCreate(domain: domain)
        let nonce = try keyStore.getNonce(domain: domain)

        guard let htu = Self.htuURL(for: request) else {
            throw PreludeSessionError.invalidConfiguration(
                "URLRequest is missing a URL; DPoP proof requires one"
            )
        }
        let method = request.httpMethod ?? "GET"

        let proof = try proofBuilder.create(
            key: key,
            method: method,
            url: htu,
            nonce: nonce,
            jti: nil,
            now: Date()
        )

        var initialRequest = request
        initialRequest.setValue(proof, forHTTPHeaderField: HTTPHeader.dpop)

        let (data, response) = try await next(initialRequest)

        if !(200..<300).contains(response.statusCode),
           let apiError = try? JSONDecoder().decode(APIErrorJSON.self, from: data),
           apiError.code == "use_dpop_nonce" {
            guard let newNonce = response.value(forHTTPHeaderField: HTTPHeader.dpopNonce) else {
                throw PreludeSessionError.generic(
                    code: "missing_dpop_nonce",
                    message: "Server requested a DPoP nonce but did not provide one"
                )
            }

            // Persist before retrying. RFC 9449 §8 requires the
            // client to use this nonce on all subsequent proofs;
            // dropping it here would force an extra challenge
            // round-trip on the next request.
            try keyStore.setNonce(domain: domain, nonce: newNonce)

            let retryProof = try proofBuilder.create(
                key: key,
                method: method,
                url: htu,
                nonce: newNonce,
                jti: nil,
                now: Date()
            )

            var retryRequest = request
            retryRequest.setValue(retryProof, forHTTPHeaderField: HTTPHeader.dpop)

            let (retryData, retryResponse) = try await next(retryRequest)
            try harvestNonce(from: retryResponse)
            return (retryData, retryResponse)
        }

        try harvestNonce(from: response)
        return (data, response)
    }

    /// URL for the DPoP `htu` claim. Must match the server's
    /// reconstruction (`scheme://Host-header/path`) when a `Host:`
    /// override is in effect. RFC 9449 §4.2 excludes query and
    /// fragment.
    static func htuURL(for request: URLRequest) -> URL? {
        guard let url = request.url,
              var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return nil
        }
        components.query = nil
        components.fragment = nil
        // Scheme and host are case-insensitive (RFC 3986 §6.2.2.1)
        // and the server's reconstruction normalizes them; mirror
        // that here so a mixed-case base URL still produces a
        // matching proof.
        components.scheme = components.scheme?.lowercased()
        components.host = components.host?.lowercased()

        if let hostOverride = request.value(forHTTPHeaderField: HTTPHeader.host),
           !hostOverride.isEmpty {
            // Use the Host header verbatim, lowercased (port
            // included) so the client `htu` matches byte-for-byte.
            // `percentEncodedPath` keeps the original encoding.
            let scheme = components.scheme ?? "https"
            return URL(string: "\(scheme)://\(hostOverride.lowercased())\(components.percentEncodedPath)")
        }

        return components.url
    }

    private func harvestNonce(from response: HTTPURLResponse) throws {
        guard let newNonce = response.value(forHTTPHeaderField: HTTPHeader.dpopNonce) else {
            return
        }
        try keyStore.setNonce(domain: domain, nonce: newNonce)
    }
}

import Foundation
import Security

/// The operations ``DefaultDPoPProofBuilder`` needs from a DPoP keypair.
/// As a protocol so ``DPoP.swift`` stays framework-free and tests can
/// supply mocks.
protocol DPoPKey: Sendable {
    /// Public key as a JWK dictionary (`kty`, `crv`, `x`, `y`).
    func exportPublicJWK() throws -> [String: String]

    /// ES256 signature in raw `r || s` form (64 bytes for P-256),
    /// as required by JWS.
    func signES256(_ data: Data) throws -> Data
}

/// Concrete ``DPoPKey`` backed by a `SecKey` pair. For Secure
/// Enclave-backed stores the private key never leaves the enclave.
///
/// `@unchecked Sendable`: fields are `private let`; `SecKey` ops
/// used here are documented thread-safe; CF retain/release is
/// atomic. The escape hatch is needed because `SecKey` isn't
/// universally `Sendable` across the SDKs we build against.
struct DPoPKeyHandle: DPoPKey, @unchecked Sendable {
    private let domain: String
    private let privateKey: SecKey
    private let publicKey: SecKey

    init(domain: String, privateKey: SecKey, publicKey: SecKey) {
        self.domain = domain
        self.privateKey = privateKey
        self.publicKey = publicKey
    }

    /// `SecKeyCopyExternalRepresentation` emits uncompressed X9.63
    /// (`0x04 || X(32) || Y(32)`); strip the tag and base64url-encode
    /// the two coordinates.
    func exportPublicJWK() throws -> [String: String] {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            _ = error?.takeRetainedValue()
            throw DPoPProofError.publicKeyExportFailed
        }

        guard data.count == 65, data[data.startIndex] == 0x04 else {
            throw DPoPProofError.invalidPublicKeyRepresentation
        }

        let xRange = data.index(data.startIndex, offsetBy: 1) ..< data.index(data.startIndex, offsetBy: 33)
        let yRange = data.index(data.startIndex, offsetBy: 33) ..< data.index(data.startIndex, offsetBy: 65)

        return [
            "kty": "EC",
            "crv": "P-256",
            "x": data[xRange].base64URLEncodedString(),
            "y": data[yRange].base64URLEncodedString(),
        ]
    }

    /// `SecKeyCreateSignature` returns DER-encoded ECDSA; convert
    /// to raw `r || s`.
    func signES256(_ data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            throw DPoPProofError.signingFailed(underlying: error?.takeRetainedValue())
        }
        return try Self.derToRawECDSASignature(der)
    }

    /// DER: `SEQUENCE INTEGER r INTEGER s`. INTEGERs are signed, so
    /// a leading `0x00` padding byte may be present; strip it then
    /// left-pad each component to 32 bytes.
    private static func derToRawECDSASignature(_ der: Data) throws -> Data {
        let bytes = [UInt8](der)
        var index = 0

        guard bytes.count >= 2, bytes[index] == 0x30 else {
            throw DPoPProofError.derSignatureMalformed
        }
        index += 1

        let sequenceLength = try readDERLength(bytes: bytes, index: &index)
        guard bytes.count - index >= sequenceLength else {
            throw DPoPProofError.derSignatureMalformed
        }

        let signatureR = try readDERInteger(bytes: bytes, index: &index)
        let signatureS = try readDERInteger(bytes: bytes, index: &index)

        return Data(leftPad(signatureR, to: 32) + leftPad(signatureS, to: 32))
    }

    private static func readDERLength(bytes: [UInt8], index: inout Int) throws -> Int {
        guard index < bytes.count else {
            throw DPoPProofError.derSignatureMalformed
        }
        let first = bytes[index]
        index += 1
        if first < 0x80 {
            return Int(first)
        }

        let numLengthBytes = Int(first & 0x7F)
        guard numLengthBytes > 0, numLengthBytes <= 2,
              bytes.count >= index + numLengthBytes else {
            throw DPoPProofError.derSignatureMalformed
        }
        var length = 0
        for offset in 0 ..< numLengthBytes {
            length = (length << 8) | Int(bytes[index + offset])
        }
        index += numLengthBytes
        return length
    }

    private static func readDERInteger(bytes: [UInt8], index: inout Int) throws -> [UInt8] {
        guard index < bytes.count, bytes[index] == 0x02 else {
            throw DPoPProofError.derSignatureMalformed
        }
        index += 1

        let length = try readDERLength(bytes: bytes, index: &index)
        guard bytes.count >= index + length else {
            throw DPoPProofError.derSignatureMalformed
        }

        var value = Array(bytes[index ..< (index + length)])
        index += length

        if value.first == 0x00, value.count > 1 {
            value.removeFirst()
        }
        guard value.count <= 32 else {
            throw DPoPProofError.derSignatureMalformed
        }
        return value
    }

    private static func leftPad(_ bytes: [UInt8], to length: Int) -> [UInt8] {
        guard bytes.count < length else { return bytes }
        return [UInt8](repeating: 0, count: length - bytes.count) + bytes
    }
}

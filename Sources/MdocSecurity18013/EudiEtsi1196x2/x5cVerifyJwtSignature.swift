/*
Copyright (c) 2026 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import Foundation
import CryptoKit
import EudiEtsi1196x2

/// A ``VerifyJwtSignature`` implementation that verifies a LoTE JWS using the X.509
/// certificate chain embedded in its `x5c` protected header (RFC 7515 §4.1.6).
///
/// The JWS signature is validated against the public key of the leaf certificate
/// (`x5c[0]`) using the algorithm declared in the `alg` header. ECDSA algorithms
/// (`ES256` / `ES384` / `ES512`) are supported, matching the signature scheme used by
/// the EUDI trust lists.
///
/// This performs the cryptographic signature check only; anchoring the `x5c` chain to a
/// trusted scheme operator is handled by the certificate-profile validation of the
/// surrounding trust pipeline.
final class x5cVerifyJwtSignature: VerifyJwtSignature, @unchecked Sendable {
    static let shared = x5cVerifyJwtSignature()

    public init() {}

    func invoke(jwt: String) async throws -> any VerifyJwtSignatureOutcome {
        do {
            try Self.verify(jwt: jwt)
            return VerifyJwtSignatureOutcomeVerified(jwt: jwt)
        } catch {
            logger.error("x5c JWT signature verification failed: \(error)")
            return VerifyJwtSignatureOutcomeNotVerified(cause: nil)
        }
    }

    enum JwtSignatureError: Error {
        case malformedJwt
        case invalidHeader
        case missingX5c
        case invalidCertificate
        case unsupportedAlgorithm(String)
        case invalidSignature
    }

    /// Verify the JWS signature against the leaf certificate carried in the `x5c` header.
    /// - Throws: ``JwtSignatureError`` when the token is malformed or the signature is invalid.
    static func verify(jwt: String) throws {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw JwtSignatureError.malformedJwt }
        let headerPart = String(parts[0])
        let payloadPart = String(parts[1])
        guard let headerData = base64urlDecode(headerPart),
              let signature = base64urlDecode(String(parts[2])) else {
            throw JwtSignatureError.malformedJwt
        }
        guard let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
            throw JwtSignatureError.invalidHeader
        }
        guard let alg = header["alg"] as? String else { throw JwtSignatureError.invalidHeader }
        // x5c entries are base64 (standard, not base64url) DER certificates; the leaf is first.
        guard let x5c = header["x5c"] as? [String], let leafBase64 = x5c.first,
              let certData = Data(base64Encoded: leafBase64) else {
            throw JwtSignatureError.missingX5c
        }
        guard let publicKeyX963 = SecurityHelpers.getPublicKeyx963(publicCertData: certData) else {
            throw JwtSignatureError.invalidCertificate
        }
        // JWS signing input is the ASCII bytes of "<header>.<payload>".
        let signingInput = Data("\(headerPart).\(payloadPart)".utf8)
        let isValid: Bool
        switch alg {
        case "ES256":
            let key = try P256.Signing.PublicKey(x963Representation: publicKeyX963)
            let sig = try P256.Signing.ECDSASignature(rawRepresentation: signature)
            isValid = key.isValidSignature(sig, for: signingInput)
        case "ES384":
            let key = try P384.Signing.PublicKey(x963Representation: publicKeyX963)
            let sig = try P384.Signing.ECDSASignature(rawRepresentation: signature)
            isValid = key.isValidSignature(sig, for: signingInput)
        case "ES512":
            let key = try P521.Signing.PublicKey(x963Representation: publicKeyX963)
            let sig = try P521.Signing.ECDSASignature(rawRepresentation: signature)
            isValid = key.isValidSignature(sig, for: signingInput)
        default:
            throw JwtSignatureError.unsupportedAlgorithm(alg)
        }
        guard isValid else { throw JwtSignatureError.invalidSignature }
    }

    /// Decode a base64url-encoded (RFC 4648 §5, no padding) string into `Data`.
    static func base64urlDecode(_ input: String) -> Data? {
        var str = input.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = str.count % 4
        if remainder > 0 { str += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: str)
    }
}

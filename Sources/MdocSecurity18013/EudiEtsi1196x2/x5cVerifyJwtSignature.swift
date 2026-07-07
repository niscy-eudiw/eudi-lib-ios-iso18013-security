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
import Security
import EudiEtsi1196x2

/// A ``VerifyJwtSignature`` implementation that verifies a LoTE JWS using the X.509
/// certificate chain embedded in its `x5c` protected header (RFC 7515 §4.1.6).
///
/// The JWS signature is validated against the public key of the leaf certificate
/// (`x5c[0]`) using the algorithm declared in the `alg` header. Both ECDSA
/// (`ES256` / `ES384` / `ES512`) and RSASSA-PKCS1-v1_5 (`RS256` / `RS384` / `RS512`)
/// algorithms are supported, matching the signature schemes used by the EUDI trust lists.
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

    enum JwtSignatureError: LocalizedError {
        case malformedJwt
        case invalidHeader
        case missingX5c
        case invalidCertificate
        case unsupportedAlgorithm(String)
        case invalidSignature

        var errorDescription: String? {
            switch self {
            case .malformedJwt:
                return NSLocalizedString("The JWT is malformed.", comment: "JwtSignatureError")
            case .invalidHeader:
                return NSLocalizedString("The JWT header is invalid.", comment: "JwtSignatureError")
            case .missingX5c:
                return NSLocalizedString("The JWT header is missing a valid x5c certificate chain.", comment: "JwtSignatureError")
            case .invalidCertificate:
                return NSLocalizedString("The leaf certificate in the x5c chain is invalid.", comment: "JwtSignatureError")
            case .unsupportedAlgorithm(let algorithm):
                let message = "The signature algorithm '\(algorithm)' is not supported."
                return NSLocalizedString(message, comment: "JwtSignatureError")
            case .invalidSignature:
                return NSLocalizedString("The JWT signature is invalid.", comment: "JwtSignatureError")
            }
        }
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
        // JWS signing input is the ASCII bytes of "<header>.<payload>".
        let signingInput = Data("\(headerPart).\(payloadPart)".utf8)
        let isValid: Bool
        switch alg {
        case "ES256":
            let key = try P256.Signing.PublicKey(x963Representation: try ecPublicKeyX963(certData: certData))
            let sig = try P256.Signing.ECDSASignature(rawRepresentation: signature)
            isValid = key.isValidSignature(sig, for: signingInput)
        case "ES384":
            let key = try P384.Signing.PublicKey(x963Representation: try ecPublicKeyX963(certData: certData))
            let sig = try P384.Signing.ECDSASignature(rawRepresentation: signature)
            isValid = key.isValidSignature(sig, for: signingInput)
        case "ES512":
            let key = try P521.Signing.PublicKey(x963Representation: try ecPublicKeyX963(certData: certData))
            let sig = try P521.Signing.ECDSASignature(rawRepresentation: signature)
            isValid = key.isValidSignature(sig, for: signingInput)
        case "RS256":
            isValid = try verifyRSA(certData: certData, signingInput: signingInput, signature: signature, algorithm: .rsaSignatureMessagePKCS1v15SHA256)
        case "RS384":
            isValid = try verifyRSA(certData: certData, signingInput: signingInput, signature: signature, algorithm: .rsaSignatureMessagePKCS1v15SHA384)
        case "RS512":
            isValid = try verifyRSA(certData: certData, signingInput: signingInput, signature: signature, algorithm: .rsaSignatureMessagePKCS1v15SHA512)
        default:
            throw JwtSignatureError.unsupportedAlgorithm(alg)
        }
        guard isValid else { throw JwtSignatureError.invalidSignature }
    }

    /// Extracts the EC public key of the leaf certificate as an x9.63 representation.
    private static func ecPublicKeyX963(certData: Data) throws -> Data {
        guard let publicKeyX963 = SecurityHelpers.getPublicKeyx963(publicCertData: certData) else {
            throw JwtSignatureError.invalidCertificate
        }
        return publicKeyX963
    }

    /// Verifies an RSASSA-PKCS1-v1_5 (`RS256` / `RS384` / `RS512`) JWS signature against the RSA
    /// public key of the leaf certificate, using the Security framework (CryptoKit has no RSA).
    private static func verifyRSA(certData: Data, signingInput: Data, signature: Data, algorithm: SecKeyAlgorithm) throws -> Bool {
        guard let certificate = SecCertificateCreateWithData(nil, certData as CFData),
              let publicKey = SecCertificateCopyKey(certificate) else {
            throw JwtSignatureError.invalidCertificate
        }
        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(publicKey, algorithm, signingInput as CFData, signature as CFData, &error)
        if let error {
            logger.error("RSA JWT signature verification error: \(error.takeRetainedValue())")
            return false
        }
        return isValid
    }

    /// Decode a base64url-encoded (RFC 4648 §5, no padding) string into `Data`.
    static func base64urlDecode(_ input: String) -> Data? {
        var str = input.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = str.count % 4
        if remainder > 0 { str += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: str)
    }
}

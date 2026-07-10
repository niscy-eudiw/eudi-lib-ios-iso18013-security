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
import Security
import EudiEtsi1196x2
import JSONWebSignature

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
public final class x5cVerifyJwtSignature: VerifyJwtSignature, @unchecked Sendable {
    public static let shared = x5cVerifyJwtSignature()

    public init() {}

    public func invoke(jwt: String) async throws -> any VerifyJwtSignatureOutcome {
    	try Self.verify(jwt: jwt)
		return VerifyJwtSignatureOutcomeVerified(jwt: jwt)
    }

    /// Verify the JWS signature against the leaf certificate carried in the `x5c` header,
    /// using the `jose-swift` `JWS` implementation.
    ///
    /// `jose-swift` selects the verification algorithm from the JWS `alg` header and supports the
    /// ECDSA (`ES256` / `ES384` / `ES512`) and RSASSA-PKCS1-v1_5 (`RS256` / `RS384` / `RS512`)
    /// schemes used by the EUDI trust lists.
    /// - Throws: `JWS.JWSError` when the token is malformed, the verifying key is missing, or the
    ///   signature is invalid. Parse and verification failures are propagated from `jose-swift`.
    public static func verify(jwt: String) throws {
        // `JWS(jwsString:)` throws `JWS.JWSError.invalidString` for a malformed token.
        let jws = try JWS(jwsString: jwt)
        // x5c entries are base64 (standard, not base64url) DER certificates; the leaf is first.
        guard let leafBase64 = jws.protectedHeader.x509CertificateChain?.first,
              let certData = Data(base64Encoded: leafBase64) else {
            throw JWS.JWSError.missingKey
        }
        // Extract the leaf certificate public key; `jose-swift` verifies against it via `SecKey`.
        guard let certificate = SecCertificateCreateWithData(nil, certData as CFData),
              let publicKey = SecCertificateCopyKey(certificate) else {
            throw JWS.JWSError.missingKey
        }
        // `verify(key:)` picks the algorithm from the header and throws `JWS.JWSError` on failure.
        guard try jws.verify(key: publicKey) else {
            throw JWS.JWSError.somethingWentWrong
        }
    }

}

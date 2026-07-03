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

public struct EtsiTrustManager: @unchecked Sendable {
    let validator: CachedTrustValidator
    /// The single verification context this manager validates certificate chains against.
    let verificationContext: VerificationContext

    /// Builds a cached LoTE-based trust validator from `config`.
    ///
    /// - Note: Only a subset of `EtsiTrustConfig` is applied. The validator is built through
    ///   `EudiwIosTrust.cached(urls:ttlHours:verifyJwtSignature:)`, which honors
    ///   `loteLocations`, `cacheTtl`, and `customJwtSignatureVerifier`. The remaining fields
    ///   (`relaxCertificateProfiles`, `relaxPkixRevocation`, `loteConstraints`,
    ///   `fileCacheExpiration`, and `classifications`) are **not** applied here: the bridged
    ///   `EudiEtsi1196x2` API does not expose the `CoroutineDispatcher` / `Clock` instances that
    ///   the full, config-honoring `ProvisionTrustAnchorsFromLoTEs.cached(...)` factory requires,
    ///   so those fields can only be honored on the non-cached path.
    public init(config: EtsiTrustConfig) {
        let lists = config.loteLocations
        let urls = TrustListUrls()
        urls.pidProviders    = lists.pidProviders as String?
        urls.walletProviders = lists.walletProviders as String?
        urls.wrpacProviders  = lists.wrpacProviders as String?
        urls.wrprcProviders  = lists.wrprcProviders as String?
        urls.pubEaaProviders = lists.pubEaaProviders as String?
        urls.qeaProviders    = lists.qeaProviders as String?
        urls.mdlProviders    = lists.eaaProviders[EudiwIosTrust.shared.mdlUseCase] as String?

        let verifyJwtSignature: VerifyJwtSignature = config.customJwtSignatureVerifier ?? x5cVerifyJwtSignature.shared
        let ttlHours = config.cacheTtl / 3600
        validator = EudiwIosTrust.shared.cached(urls: urls, ttlHours: ttlHours, verifyJwtSignature: verifyJwtSignature)
        verificationContext = config.verificationContext
    }

    /// Trust manager for the EC DIGIT acceptance environment.
    public static let digi: Self = Self(config: .digi)

    /// Trust manager for the EUDI Wallet Reference Implementation environment.
    public static let eudiRef: Self = Self(config: .eudiRef)
}

// MARK: - ReaderTrustStore

extension EtsiTrustManager: ReaderTrustStore {
    public func createCertificationTrustPath(chain: [SecCertificate]) async -> [SecCertificate]? {
        let derChain = chain.map { SecCertificateCopyData($0) as Data }
        guard let result = await validate(derChain: derChain), result.isTrusted else { return nil }

        // Append the matched trust anchor to complete the path when it is not already present.
        var path = chain
        if let anchorData = result.matchedAnchor,
           !derChain.contains(anchorData),
           let anchorCert = SecCertificateCreateWithData(nil, anchorData as CFData) {
            path.append(anchorCert)
        }
        return path
    }

    public func validateCertificationTrustPath(chainToDocumentSigner: [SecCertificate]) async -> Bool {
        let derChain = chainToDocumentSigner.map { SecCertificateCopyData($0) as Data }
        return await validate(derChain: derChain)?.isTrusted ?? false
    }

    /// Runs the async ETSI validator. Returns `nil` if validation throws or the context is
    /// unsupported by the validator.
    private func validate(derChain: [Data]) async -> IosValidationResult? {
        try? await validator.validate(chain: derChain, context: verificationContext)
    }
}



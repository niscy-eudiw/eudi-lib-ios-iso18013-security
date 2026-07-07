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
    /// Type-erased validation over the selected trust source; returns `nil` if validation throws
    /// or the context is unsupported. Bridges the two validator kinds (cached LoTE vs. bundled
    /// anchors), which the `EudiEtsi1196x2` API exposes through different entry points.
    private let validateChain: ([Data], any VerificationContext) async -> IosValidationResult?
    let contextTypeMappings: EtsiContextTypeMappings?
    public var docType: String?

    /// Builds a trust manager from the selected `TrustConfig`.
    ///
    /// - `.etsi`: a cached LoTE validator via `EudiwIosTrust.cached(urls:ttlHours:verifyJwtSignature:)`,
    ///   which honors `loteLocations`, `cacheTtl`, and `customJwtSignatureVerifier`. The remaining
    ///   `EtsiTrustConfig` fields (`relaxCertificateProfiles`, `relaxPkixRevocation`,
    ///   `loteConstraints`, `fileCacheExpiration`) are **not** applied: the bridged API does not
    ///   expose the `CoroutineDispatcher` / `Clock` instances the full,
    ///   source-honoring `ProvisionTrustAnchorsFromLoTEs.cached(...)` factory requires.
    /// - `.staticList`: a bundled-anchors validator via `EudiwIosTrust.usingBundledAnchors(anchors:method:)`
    ///   — no LoTE download, no network.
    public init(source: TrustSource) {
        contextTypeMappings = source.contextTypeMappings
        switch source {
        case .etsi(let etsi):
            let lists = etsi.loteLocations
            let urls = TrustListUrls()
            urls.pidProviders = lists.pidProviders as String?
            urls.walletProviders = lists.walletProviders as String?
            urls.wrpacProviders = lists.wrpacProviders as String?
            urls.wrprcProviders = lists.wrprcProviders as String?
            urls.pubEaaProviders = lists.pubEaaProviders as String?
            urls.qeaProviders = lists.qeaProviders as String?
            urls.mdlProviders = lists.eaaProviders[EudiwIosTrust.shared.mdlUseCase] as String?

            let verifyJwtSignature: VerifyJwtSignature = etsi.customJwtSignatureVerifier ?? x5cVerifyJwtSignature.shared
            let ttlHours = etsi.cacheTtl / 3600
            let validator = EudiwIosTrust.shared.cached(urls: urls, ttlHours: ttlHours, verifyJwtSignature: verifyJwtSignature)
            validateChain = { chain, context in
                do {
                    let iosVal = try await validator.validate(chain: chain, context: context)
                    if let failReason = iosVal.failureReason { logger.warning("ETSI LoTE not trusted reason: \(failReason)")}
                    return iosVal
              } catch {
                    logger.error("ETSI LoTE chain validation failed: \(error)")
                    return nil
                }
            }
        case .staticList(let staticList):
            let validator = EudiwIosTrust.shared.usingBundledAnchors(anchors: staticList.bundledAnchors, method: staticList.method)
            validateChain = { chain, context in
                do {
                    let iosVal = try await EudiwIosTrust.shared.validate(validator: validator, chain: chain, context: context)
                    if let failReason = iosVal.failureReason { logger.warning("Bundled-anchors not trusted reason: \(failReason)")}
                    return iosVal
                } catch {
                    logger.error("Bundled-anchors chain validation failed: \(error)")
                    return nil
                }
            }
        }
    }

    /// Convenience initializer for an ETSI LoTE trust source.
    public init(source: EtsiTrustSource) {
        self.init(source: .etsi(source))
    }

    /// Convenience initializer for a static bundled-anchors trust source.
    public init(source: StaticListTrustSource) {
        self.init(source: .staticList(source))
    }

    /// The verification context this configuration validates certificate chains against
    /// (e.g. PID, Wallet, WRPAC). `EtsiTrustManager` uses it as its single trust context.
    public var verificationContext: any VerificationContext {
        if let contextTypeMappings, let docType, let contextType = contextTypeMappings[docType] {
            return contextType.verificationContext
        }
        return EtsiContextType.wrpac.verificationContext
    }
  

    /// Trust manager for the EC DIGIT acceptance environment.
    public static let digi: Self = Self(source: .digi)

    /// Trust manager for the EUDI Wallet Reference Implementation environment.
    public static let eudiRef: Self = Self(source: .eudiRef)
}

// MARK: - ReaderTrustStore

extension EtsiTrustManager: CertificateTrustValidator {
    public func createCertTrustPath(chain: [Data]) async -> [Data]? {
        guard let result = await validate(chain: chain), result.isTrusted else { return nil }
        // Append the matched trust anchor to complete the path when it is not already present.
        var path = chain
        if let anchorData = result.matchedAnchor, !chain.contains(anchorData) {
            path.append(anchorData)
        }
        return path
    }

    public func validateCertTrustPath(chain: [Data]) async -> Bool {
        await validate(chain: chain)?.isTrusted ?? false
    }

    /// Runs the async validator for the configured trust source. Returns `nil` if validation
    /// throws or the context is unsupported by the validator.
    private func validate(chain: [Data]) async -> IosValidationResult? {
        await validateChain(chain, verificationContext)
    }
}



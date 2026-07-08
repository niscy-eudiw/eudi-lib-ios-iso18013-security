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

/// Configuration that describes where trust anchors come from and how trust failures are handled.
public struct TrustConfiguration: Sendable {
    /// The source the trust anchors are built from.
    public let trustSource: TrustSource
    /// The policy applied to doc types without a specific entry in `docTypePolicies`.
    public let defaultPolicy: TrustPolicy
    /// Per doc-type overrides of `defaultPolicy`, keyed by doc type.
    public let docTypePolicies: [String: TrustPolicy]

    /// Trust manager for issuer (document-signer) certificates. Falls back to the `default`
    /// doc-type mappings only when the trust source does not already define its own.
    public let issuerTrustManager: EtsiTrustManager

    /// Trust manager for reader/relying-party access certificates. Uses the WRPAC verification context.
    public let accessTrustManager: EtsiTrustManager

    public init(
        trustSource: TrustSource,
        defaultPolicy: TrustPolicy = .enforce,
        docTypePolicies: [String: TrustPolicy] = [:]
    ) {
        self.trustSource = trustSource
        self.defaultPolicy = defaultPolicy
        self.docTypePolicies = docTypePolicies
        let issuerSource = trustSource.contextTypeMappings == nil
            ? trustSource.withContextTypeMappings(.default)
            : trustSource
        self.issuerTrustManager = EtsiTrustManager(source: issuerSource)
        self.accessTrustManager = EtsiTrustManager(source: trustSource.withContextTypeMappings(nil))
    }

    /// The trust policy effective for the given doc type, falling back to `defaultPolicy`.
    public func policy(for docType: String) -> TrustPolicy {
        docTypePolicies[docType] ?? defaultPolicy
    }
}

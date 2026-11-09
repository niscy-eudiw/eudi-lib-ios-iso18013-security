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

#if canImport(EudiEtsi1196x2)
import Foundation
import EudiEtsi1196x2

/// Checks a DER certificate against the CRLs advertised in its distribution points.
///
/// Pass an instance as `crlChecker` to `EtsiTrustSource` or `StaticListTrustSource`.
/// The PKIX bridge calls this synchronous checker on a background thread; downloads may block.
/// A positive result requires a current CRL signed by the supplied issuer. Missing, malformed,
/// stale or unsupported evidence returns `Unknown`, allowing the configured OCSP fallback.
/// Supports DER/PEM v2 CRLs with UTC time fields and complete, direct HTTP(S) distribution
/// points. Delta, indirect and scoped CRLs and critical CRL extensions are unsupported.
public final class CheckCRLRevocation: NSObject, CheckRevocationIos {
    private let checker: CRLRevocationChecker

    public override init() {
        checker = CRLRevocationChecker()
        super.init()
    }

    init(load: @escaping (URL) throws -> Data) {
        checker = CRLRevocationChecker(load: load)
        super.init()
    }

    public func invoke(certificate: Data, issuer: Data) -> any IosRevocationStatus {
        switch checker.check(certificate: certificate, issuer: issuer) {
        case .good: IosRevocationStatusGood.shared
        case .revoked(let reason): IosRevocationStatusRevoked(reason: reason)
        case .unknown(let reason): IosRevocationStatusUnknown(reason: reason)
        }
    }
}
#endif

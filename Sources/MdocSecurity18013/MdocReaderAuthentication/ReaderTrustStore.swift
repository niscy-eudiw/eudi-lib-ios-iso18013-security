/*
Copyright (c) 2023-2026 European Commission

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

/// Interface that defines a trust manager, used to check the validity of a
/// document signer and the associated certificate chain.
///
/// Note that each document type should have a different trust manager; this
/// trust manager is selected by OID in the DS certificate. These trust managers
/// should have a specific trust store for each certificate and may implement
/// specific checks required for the document type.
public protocol ReaderTrustStore {
    /// Creates a certification trust path by finding a certificate in the trust store
    /// that is the issuer of a certificate in the certificate chain.
    /// Returns `nil` if no trusted certificate can be found.
    ///
    /// - Parameter chain: the chain, leaf certificate first, followed by any certificate
    ///   that signed the previous certificate.
    /// - Returns: the certification path in the same order, or `nil` if no certification
    ///   trust path could be created.
    func createCertificationTrustPath(chain: [SecCertificate]) async -> [SecCertificate]?

    /// Validates that the given certificate chain is a valid chain that includes a document
    /// signer. Accepts a chain of certificates, starting with the document signer certificate,
    /// followed by any intermediate certificates up to the optional root certificate.
    ///
    /// The trust manager should be initialized with a set of trusted certificates. The chain
    /// is trusted if a trusted certificate can be found that has signed any certificate in the
    /// chain. The trusted certificate itself will be validated as well.
    ///
    /// - Parameter chainToDocumentSigner: the document signer, intermediate certificates and
    ///   optional root certificate.
    /// - Returns: `false` if no trusted certificate could be found for the certificate chain
    ///   or if the certificate chain is invalid for any reason.
    func validateCertificationTrustPath(chainToDocumentSigner: [SecCertificate]) async -> Bool
}

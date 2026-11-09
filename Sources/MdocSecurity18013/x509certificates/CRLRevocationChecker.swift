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
import SwiftASN1
import X509

/// Checks complete, directly issued CRLs. Path validation remains the caller's responsibility.
struct CRLRevocationChecker {
    enum Status: Equatable {
        case good
        case revoked(String)
        case unknown(String)
    }

    var load: (URL) throws -> Data = { try Data(contentsOf: $0) }

    func check(certificate: Data, issuer: Data) -> Status {
        do {
            let certificate = try Certificate(derEncoded: Array(certificate))
            let issuer = try Certificate(derEncoded: Array(issuer))
            guard certificate.issuer == issuer.subject,
                  issuer.publicKey.isValidSignature(certificate.signature, for: certificate) else {
                return .unknown("Certificate was not issued by the supplied issuer")
            }
            if let usage = try issuer.extensions.keyUsage, !usage.cRLSign {
                return .unknown("Issuer key usage does not permit CRL signing")
            }
            let urls = try distributionPoints(certificate)
            guard !urls.isEmpty else { return .unknown("No supported CRL distribution point") }
            var reasons = [String]()
            var hasGoodResponse = false
            for url in urls {
                do {
                    let data = try load(url)
                    let crl: CRL
                    if let pem = String(data: data, encoding: .utf8), pem.contains("-----BEGIN") {
                        crl = try CRL(pemEncoded: pem)
                    } else {
                        crl = try CRL(derEncoded: Array(data))
                    }
                    guard crl.version == 1, crl.supportsDirectRevocationCheck else {
                        reasons.append("Unsupported CRL scope or extensions")
                        continue
                    }
                    guard crl.issuer == issuer.subject, crl.verifySignature(issuer: issuer) else {
                        reasons.append("CRL issuer or signature does not match the supplied issuer")
                        continue
                    }
                    guard crl.isValid else {
                        reasons.append("CRL is outside its validity period")
                        continue
                    }
                    if crl.revokedSerials.contains(where: { $0.serial == certificate.serialNumber }) {
                        return .revoked("Certificate serial \(certificate.serialNumber) is listed in CRL at \(url)")
                    }
                    hasGoodResponse = true
                } catch {
                    reasons.append("CRL at \(url): \(error.localizedDescription)")
                }
            }
            return hasGoodResponse ? .good : .unknown(reasons.joined(separator: "; "))
        } catch {
            return .unknown("Unable to check CRL revocation: \(error.localizedDescription)")
        }
    }

    private func distributionPoints(_ certificate: Certificate) throws -> [URL] {
        guard let ext = certificate.extensions[oid: .X509ExtensionID.cRLDistributionPoints] else { return [] }
        return try DER.sequence(DER.parse(ext.value), identifier: .sequence) { points in
            var urls = [URL]()
            while let point = points.next() {
                guard point.identifier == .sequence, case .constructed(let fields) = point.content else {
                    throw CRL.toError(node: point)
                }
                let parts = Array(fields)
                // Only fullName points without reasons or a delegated cRLIssuer are supported.
                guard parts.count == 1,
                      parts[0].identifier == ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific),
                      case .constructed(let names) = parts[0].content else { continue }
                let namesArray = Array(names)
                guard namesArray.count == 1,
                      namesArray[0].identifier == ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific),
                      case .constructed(let generalNames) = namesArray[0].content else { continue }
                for name in generalNames {
                    guard name.identifier == ASN1Identifier(tagWithNumber: 6, tagClass: .contextSpecific),
                          case .primitive(let bytes) = name.content,
                          let string = String(bytes: bytes, encoding: .ascii),
                          let url = URL(string: string),
                          ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
                          url.host != nil else { continue }
                    if !urls.contains(url) { urls.append(url) }
                }
            }
            return urls
        }
    }
}

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

import CryptoKit
import Foundation
import SwiftASN1
import Testing
import X509

@testable import MdocSecurity18013

@Suite("CRL revocation checker")
struct CRLRevocationCheckerTests {
    @Test("Only authenticated, current, complete CRLs establish status", arguments: [
        "good", "revoked", "expired", "future", "signature", "issuer", "delta", "scope", "critical", "malformed", "download", "missing", "keyUsage"
    ])
    func checksEvidence(_ scenario: String) throws {
        let fixture = try Fixture(scenario: scenario)
        let checker = CRLRevocationChecker { url in
            #expect(url.absoluteString == "https://example.invalid/leaf.crl")
            if scenario == "download" { throw URLError(.notConnectedToInternet) }
            return scenario == "malformed" ? Data([0xff]) : fixture.crl
        }
        let result = checker.check(certificate: fixture.leaf, issuer: fixture.issuer)
        switch (scenario, result) {
        case ("good", .good), ("revoked", .revoked): break
        case (_, .unknown(let reason)):
            #expect(scenario != "good" && scenario != "revoked")
            #expect(!reason.isEmpty)
        default: Issue.record("Unexpected result for \(scenario): \(result)")
        }
    }

    @Test("PEM CRLs are accepted")
    func pem() throws {
        let fixture = try Fixture()
        let pem = "-----BEGIN X509 CRL-----\n\(fixture.crl.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]))\n-----END X509 CRL-----"
        let checker = CRLRevocationChecker { _ in Data(pem.utf8) }
        #expect(checker.check(certificate: fixture.leaf, issuer: fixture.issuer) == .good)
    }

    @Test("Malformed inputs and unrelated issuer cannot establish status")
    func invalidInputs() throws {
        let fixture = try Fixture()
        let other = try Fixture()
        let checker = CRLRevocationChecker { _ in
            Issue.record("Invalid input should not trigger a download")
            return fixture.crl
        }
        for (leaf, issuer) in [(Data(), fixture.issuer), (fixture.leaf, Data()), (fixture.leaf, other.issuer)] {
            guard case .unknown = checker.check(certificate: leaf, issuer: issuer) else {
                Issue.record("Expected unknown")
                continue
            }
        }
    }

    #if canImport(EudiEtsi1196x2)
    @Test("Kotlin protocol receives the corresponding statuses")
    func bridge() throws {
        for scenario in ["good", "revoked", "expired"] {
            let fixture = try Fixture(scenario: scenario)
            let checker: any CheckRevocationIos = CheckCRLRevocation { _ in fixture.crl }
            let result = checker.invoke(certificate: fixture.leaf, issuer: fixture.issuer)
            switch scenario {
            case "good": #expect(result is IosRevocationStatusGood)
            case "revoked": #expect(result is IosRevocationStatusRevoked)
            default: #expect(result is IosRevocationStatusUnknown)
            }
        }
    }
    #endif

    private struct Fixture {
        let leaf: Data
        let issuer: Data
        let crl: Data

        init(scenario: String = "good") throws {
            let key = P256.Signing.PrivateKey()
            let name = try DistinguishedName { CommonName("CRL test issuer") }
            let issuerCertificate = try Certificate(
                version: .v3, serialNumber: 1, publicKey: .init(key.publicKey),
                notValidBefore: Date(timeIntervalSince1970: 1_577_836_800),
                notValidAfter: Date(timeIntervalSince1970: 2_208_988_800),
                issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
                extensions: Certificate.Extensions {
                    KeyUsage(keyCertSign: true, cRLSign: scenario != "keyUsage")
                }, issuerPrivateKey: .init(key)
            )
            var extensions = [Certificate.Extension]()
            if scenario != "missing" {
                let point = tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa0, tlv(0x86, Array("https://example.invalid/leaf.crl".utf8))))))
                extensions.append(.init(oid: .X509ExtensionID.cRLDistributionPoints, critical: false, value: point[...]))
            }
            let certificate = try Certificate(
                version: .v3, serialNumber: 2, publicKey: .init(key.publicKey),
                notValidBefore: issuerCertificate.notValidBefore, notValidAfter: issuerCertificate.notValidAfter,
                issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
                extensions: .init(extensions), issuerPrivateKey: .init(key)
            )
            issuer = Data(try der(issuerCertificate))
            leaf = Data(try der(certificate))
            let algorithm: [UInt8] = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]
            let crlName = scenario == "issuer" ? try DistinguishedName { CommonName("Other CA") } : name
            var body = [UInt8]([0x02, 0x01, 0x01]) + algorithm + (try der(crlName))
            body += tlv(0x17, Array((scenario == "future" ? "390101000000Z" : "200101000000Z").utf8))
            body += tlv(0x17, Array((scenario == "expired" ? "210101000000Z" : "400101000000Z").utf8))
            if scenario == "revoked" {
                body += tlv(0x30, tlv(0x30, [0x02, 0x01, 0x02] + tlv(0x17, Array("200101000000Z".utf8))))
            }
            if ["delta", "scope", "critical"].contains(scenario) {
                let oid: UInt8 = scenario == "delta" ? 27 : scenario == "scope" ? 28 : 99
                let critical: [UInt8] = scenario == "critical" ? [0x01, 0x01, 0xff] : []
                body += tlv(0xa0, tlv(0x30, tlv(0x30, [0x06, 0x03, 0x55, 0x1d, oid] + critical + tlv(0x04, [0x02, 0x01, 0x01]))))
            }
            let tbs = tlv(0x30, body)
            let signingKey = scenario == "signature" ? P256.Signing.PrivateKey() : key
            let signature = try signingKey.signature(for: tbs).derRepresentation
            crl = Data(tlv(0x30, tbs + algorithm + tlv(0x03, [0] + signature)))
        }
    }
}

#if canImport(EudiEtsi1196x2)
import EudiEtsi1196x2
#endif

private func tlv(_ tag: UInt8, _ bytes: [UInt8]) -> [UInt8] {
    let length: [UInt8] = bytes.count < 128 ? [UInt8(bytes.count)] :
        bytes.count < 256 ? [0x81, UInt8(bytes.count)] : [0x82, UInt8(bytes.count >> 8), UInt8(bytes.count & 255)]
    return [tag] + length + bytes
}

private func der<T: DERSerializable>(_ value: T) throws -> [UInt8] {
    var serializer = DER.Serializer()
    try serializer.serialize(value)
    return serializer.serializedBytes
}

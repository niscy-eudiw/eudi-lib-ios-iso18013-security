import Foundation
import CryptoKit
import Testing
import SwiftCBOR
import X509
import MdocDataModel18013
@testable import MdocSecurity18013

struct ReaderAuthAllTests {
    let transcript = SessionTranscript(handOver: .null)
    func request(items: [CBOR], info: CBOR? = nil) throws -> DeviceRequest {
        var value: CBOR = .map([.utf8String("version"): .utf8String("1.1"),
            .utf8String("docRequests"): .array(items.map { .map([.utf8String("itemsRequest"): $0]) })])
        if let info { value["deviceRequestInfo"] = info }
        return try DeviceRequest(cbor: value)
    }
    var items: [CBOR] {
        ["mdl", "pid"].map { type in
            CBOR.map([.utf8String("docType"): .utf8String(type),
                .utf8String("nameSpaces"): .map([.utf8String("ns"): .map([.utf8String("field"): .boolean(false)])])]).taggedEncoded
        }
    }
    @Test func signatureBindsExactInfoDocumentOrderAndTranscript() async throws {
        let signer = try Signer()
        let info = CBOR.tagged(.encodedCBORDataItem, .byteString([0xbf,0x61,0x78,0x18,0x01,0xff]))
        // Sign the normative structure independently of ReaderAuthenticationAll.toCBOR.
        let payload = CBOR.array([.utf8String("ReaderAuthenticationAll"), transcript.toCBOR(options: CBOROptions()),
            .array(items), info]).taggedEncoded.encode()
        let raw = try signer.sign(payload)
        let validator = MdocReaderAuthentication(transcript: transcript)
        let original = try request(items: items, info: info)
        let valid = try await validator.validateReaderAuthAll(readerAuthCBOR: raw, readerAuthX5c: [signer.der],
            deviceRequest: original, trustValidator: Trust(accepted: true))
        #expect(valid.0)
        let reParsed = try DeviceRequest(data: original.encode(options: CBOROptions()))
        #expect(try await validator.validateReaderAuthAll(readerAuthCBOR: raw, readerAuthX5c: [signer.der],
            deviceRequest: reParsed, trustValidator: Trust(accepted: true)).0)
        let mutations = [try request(items: Array(items.reversed()), info: info), try request(items: items),
            try request(items: items, info: CBOR.map([.utf8String("x"): .unsignedInt(1)]).taggedEncoded)]
        for changed in mutations {
            let result = try await validator.validateReaderAuthAll(readerAuthCBOR: raw, readerAuthX5c: [signer.der],
                deviceRequest: changed, trustValidator: Trust(accepted: true))
            #expect(!result.0)
        }
        let changedTranscript = MdocReaderAuthentication(transcript: SessionTranscript(handOver: .utf8String("other")))
        let wrongTranscript = try await changedTranscript.validateReaderAuthAll(readerAuthCBOR: raw, readerAuthX5c: [signer.der],
            deviceRequest: original, trustValidator: Trust(accepted: true))
        #expect(!wrongTranscript.0)
    }
    @Test func missingInfoUsesNullAndTrustIsMandatory() async throws {
        let signer = try Signer()
        let payload = CBOR.array([.utf8String("ReaderAuthenticationAll"), transcript.toCBOR(options: CBOROptions()),
            .array(items), .null]).taggedEncoded.encode()
        let raw = try signer.sign(payload)
        let request = try request(items: items)
        let validator = MdocReaderAuthentication(transcript: transcript)
        let accepted = try await validator.validateReaderAuthAll(readerAuthCBOR: raw, readerAuthX5c: [signer.der], deviceRequest: request, trustValidator: Trust(accepted: true))
        let rejected = try await validator.validateReaderAuthAll(readerAuthCBOR: raw, readerAuthX5c: [signer.der], deviceRequest: request, trustValidator: Trust(accepted: false))
        #expect(accepted.0)
        #expect(!rejected.0)
        #expect(rejected.1 == "Untrusted reader")
    }
    @Test func malformedCoseAndMismatchedCertificateAreRejectedWithoutTrapping() async throws {
        let signer = try Signer()
        let raw = try signer.sign([1])
        let validator = MdocReaderAuthentication(transcript: transcript)
        let request = try request(items: items)
        for value in [CBOR.array([]), .array([.byteString([])]), raw] {
            let result = try await validator.validateReaderAuthAll(readerAuthCBOR: value, readerAuthX5c: [Data([1])],
                deviceRequest: request, trustValidator: Trust(accepted: true))
            #expect(!result.0)
        }
    }
    private struct Trust: CertificateTrustValidator {
        var docType: String?
        let accepted: Bool
        func createCertTrustPath(chain: [Data]) async -> [Data]? { chain }
        func validateCertTrustPath(chain: [Data]) async -> (Bool, String?) { (accepted, accepted ? nil : "Untrusted reader") }
    }
    private struct Signer {
        let key = P256.Signing.PrivateKey()
        let der: Data
        init() throws {
            let privateKey = Certificate.PrivateKey(key)
            let name = try DistinguishedName { CommonName("Reader") }
            let certificate = try Certificate(version: .v3, serialNumber: .init(), publicKey: privateKey.publicKey,
                notValidBefore: Date() - 60, notValidAfter: Date() + 3600, issuer: name, subject: name,
                extensions: Certificate.Extensions {}, issuerPrivateKey: privateKey)
            der = Data(try certificate.serializeAsPEM().derBytes)
        }
        func sign(_ payload: [UInt8]) throws -> CBOR {
            let header = CBOR.map([1: .negativeInt(6)]).encode()
            let input = CBOR.array([.utf8String("Signature1"), .byteString(header), .byteString([]), .byteString(payload)]).encode()
            let signature = try key.signature(for: Data(input)).rawRepresentation
            return .array([.byteString(header), .map([33: .byteString(Array(der))]), .null, .byteString(Array(signature))])
        }
    }
}

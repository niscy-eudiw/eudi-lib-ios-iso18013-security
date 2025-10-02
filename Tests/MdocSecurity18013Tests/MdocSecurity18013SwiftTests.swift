/*
Copyright (c) 2023 European Commission

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

import Testing
import Foundation
import SwiftCBOR

@testable import MdocDataModel18013
@testable import MdocSecurity18013

@Suite("MdocSecurity18013 Swift Testing Suite")
struct MdocSecurity18013SwiftTests {
    
    @Test("Decode session transcript from annex d51")
    func testDecodeSessionTranscriptAnnexD51() throws {
        let d = try #require(try CBOR.decode([UInt8](MdocSecurityTestData.AnnexdTestData.d51_sessionTranscriptData)))
        
        guard case let .tagged(_, v) = d, 
              case let .byteString(bs) = v, 
              let st = try CBOR.decode(bs) else {
            Issue.record("Not a tagged cbor")
            return
        }
        
        let transcript = try #require(SessionTranscript(cbor: st))
        #expect(transcript != nil)
    }
    
    @Test("Decode session establishment from annex d51")
    func testDecodeSessionEstablishmentAnnexD51() throws {
        let d = try #require(try CBOR.decode([UInt8](MdocSecurityTestData.AnnexdTestData.d51_sessionEstablishData)))
        let se: SessionEstablishment = try #require(SessionEstablishment(cbor: d))
        #expect(se != nil)
    }
    
    @Test("Decode session data from annex d51")
    func testDecodeSessionDataAnnexD51() throws {
        let d = try #require(try CBOR.decode([UInt8](MdocSecurityTestData.AnnexdTestData.d51_sessionData)))
        let sd = try #require(SessionData(cbor: d))
        #expect(sd.data != nil)
        #expect(sd.status == nil)
    }
    
    @Test("Decode session termination from annex d51")
    func testDecodeSessionTerminationAnnexD51() throws {
        let d = try #require(try CBOR.decode([UInt8](MdocSecurityTestData.AnnexdTestData.d51_sessionTermination)))
        let sd = try #require(SessionData(cbor: d))
        #expect(sd.data == nil)
        #expect(sd.status != nil)
    }
    
    func makeSessionEncryptionFromAnnexData() throws -> (SessionEstablishment, SessionEncryption) {
        let d = try #require(try CBOR.decode([UInt8](MdocSecurityTestData.AnnexdTestData.d51_sessionTranscriptData)))
        
        guard case let .tagged(t, v) = d, 
              t == .encodedCBORDataItem, 
              case let .byteString(bs) = v, 
              let st = try CBOR.decode(bs) else {
            Issue.record("Not a tagged cbor")
            throw TestError.invalidCBOR
        }
        
        let transcript = try #require(SessionTranscript(cbor: st))
        let dse = try #require(try CBOR.decode([UInt8](MdocSecurityTestData.AnnexdTestData.d51_sessionEstablishData)))
        let se: SessionEstablishment = try #require(SessionEstablishment(cbor: dse))
        var de = try #require(DeviceEngagement(data: transcript.devEngRawData!))
        de.privateKey = MdocSecurityTestData.AnnexdTestData.d51_ephDeviceKey
        var sessionEncr = try #require(SessionEncryption(se: se, de: de, handOver: transcript.handOver))
        sessionEncr.deviceEngagementRawData = try #require(transcript.devEngRawData)
        
        return (se, sessionEncr)
    }
    
    @Test("Decrypt session establishment from annex d51")
    func testDecryptSessionEstablishmentAnnexD51() async throws {
        let (se, sessionEncr) = try makeSessionEncryptionFromAnnexData()
        #expect(Data(sessionEncr.sessionTranscriptBytes) == MdocSecurityTestData.AnnexdTestData.d51_sessionTranscriptData)
        
        let d = try await sessionEncr.decrypt(se.data)
        let data = try #require(d)
        let cbor = try #require(try CBOR.decode(data))
        print("Decrypted request:\n", cbor)
    }
    
    @Test("Compute DeviceAuthenticationBytes and MacStructure from annex d53")
    func testComputeDeviceAuthenticationBytesAndMacStructureAnnexD53() async throws {
        let (_, sessionEncr) = try makeSessionEncryptionFromAnnexData()
        var authKeys = CoseKeyExchange(
            publicKey: MdocSecurityTestData.AnnexdTestData.d51_ephReaderKey.key, 
            privateKey: MdocSecurityTestData.AnnexdTestData.d53_deviceKey
        )
        
        if authKeys.privateKey.privateKeyId == nil { 
            try await authKeys.privateKey.makeKey(curve: CoseEcCurve.P256) 
        }
        
        let mdocAuth = MdocAuthentication(sessionTranscript: sessionEncr.sessionTranscript, authKeys: authKeys)
        let da = DeviceAuthentication(
            sessionTranscript: mdocAuth.sessionTranscript, 
            docType: "org.iso.18013.5.1.mDL", 
            deviceNameSpacesRawData: [0xA0]
        )
        
        let deviceAuthBytes = Data(da.toCBOR(options: CBOROptions()).taggedEncoded.encode(options: CBOROptions()))
        #expect(deviceAuthBytes == MdocSecurityTestData.AnnexdTestData.d53_deviceAuthDeviceAuthenticationBytes)
        
        let coseIn = Cose(
            type: .mac0, 
            algorithm: Cose.MacAlgorithm.hmac256.rawValue, 
            payloadData: MdocSecurityTestData.AnnexdTestData.d53_deviceAuthDeviceAuthenticationBytes
        )
        let dataToSign = try #require(coseIn.signatureStruct)
        #expect(dataToSign == MdocSecurityTestData.AnnexdTestData.d53_deviceAuthMacStructure)
    }
    
    @Test("Compute deviceAuth CBOR data")
    func testComputeDeviceAuthCBORData() async throws {
        let (_, sessionEncr) = try makeSessionEncryptionFromAnnexData()
        var authKeys = CoseKeyExchange(
            publicKey: MdocSecurityTestData.AnnexdTestData.d51_ephReaderKey.key, 
            privateKey: MdocSecurityTestData.AnnexdTestData.d53_deviceKey
        )
        
        if authKeys.privateKey.privateKeyId == nil { 
            try await authKeys.privateKey.makeKey(curve: CoseEcCurve.P256) 
        }
        
        let mdocAuth = MdocAuthentication(sessionTranscript: sessionEncr.sessionTranscript, authKeys: authKeys)
        let bUseDeviceSign = UserDefaults.standard.bool(forKey: "PreferDeviceSignature")
        let dAuthO = try await mdocAuth.getDeviceAuthForTransfer(
            docType: "org.iso.18013.5.1.mDL", 
            deviceNameSpacesRawData: [0xA0],
            dauthMethod: bUseDeviceSign ? .deviceSignature : .deviceMac, 
            unlockData: nil
        )
        
        let deviceAuth = try #require(dAuthO)
        let ourDeviceAuthCBORbytes = deviceAuth.encode(options: CBOROptions())
        #expect(Data(ourDeviceAuthCBORbytes) == MdocSecurityTestData.AnnexdTestData.d53_deviceAuthCBORdata)
    }
    
    @Test("Validate readerAuth CBOR data")
    func testValidateReaderAuthCBORData() throws {
        let (_, sessionEncr) = try makeSessionEncryptionFromAnnexData()
        let dr = try #require(DeviceRequest(data: MdocSecurityTestData.AnnexdTestData.request_d411.bytes))
        
        for docR in dr.docRequests {
            let mdocAuth = MdocReaderAuthentication(transcript: sessionEncr.sessionTranscript)
            guard let readerAuthRawCBOR = docR.readerAuthRawCBOR else { continue }
            
            let (b, message) = try mdocAuth.validateReaderAuth(
                readerAuthCBOR: readerAuthRawCBOR, 
                readerAuthX5c: docR.readerCertificates, 
                itemsRequestRawData: docR.itemsRequestRawData!
            )
            
            #expect(!b, "Current date not in validity period of Certificate")
            print(message ?? "")
        }
    }
}

// Helper error type for testing
enum TestError: Error {
    case invalidCBOR
}

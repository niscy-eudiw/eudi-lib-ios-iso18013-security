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

import Foundation
import CryptoKit
import Security
import MdocDataModel18013
/// Software secure area
///
/// This SecureArea implementation uses iOS Cryptokit framework
public actor SoftwareSecureArea: SecureArea {

    var storage: any SecureKeyStorage
    init(storage: any SecureKeyStorage) {
        self.storage = storage
    }
    public func getStorage() async -> any MdocDataModel18013.SecureKeyStorage { storage }

    nonisolated public static func create(storage: any MdocDataModel18013.SecureKeyStorage) -> SoftwareSecureArea {
        SoftwareSecureArea(storage: storage)
    }
    /// make key and return key tag
    public func createKey(id: String, keyOptions: KeyOptions?) async throws -> CoseKey {
        let x963Priv: Data; let x963Pub: Data
        let curve = keyOptions?.curve ?? .P256
        switch curve {
        case .P256: let key = P256.Signing.PrivateKey(compactRepresentable: false); x963Priv = key.x963Representation; x963Pub = key.publicKey.x963Representation
        case .P384: let key = P384.Signing.PrivateKey(compactRepresentable: false); x963Priv = key.x963Representation; x963Pub = key.publicKey.x963Representation
        case .P521: let key = P521.Signing.PrivateKey(compactRepresentable: false); x963Priv = key.x963Representation; x963Pub = key.publicKey.x963Representation
        default: throw SecureAreaError("Unsupported curve \(curve)")
        }
        try await storage.writeKeyInfo(id: id, dict: [kSecValueData as String: x963Pub, kSecAttrDescription as String: curve.jwkName.data(using: .utf8)!])
        try await storage.writeKeyData(id: id, dict: [kSecValueData as String: x963Priv], keyOptions: keyOptions)
        return CoseKey(crv: curve, x963Representation: x963Pub)
    }

    /// delete key
    public func deleteKey(id: String) async throws {
        try await storage.deleteKey(id: id)
    }
    /// compute signature
    public func signature(id: String, algorithm: SigningAlgorithm, dataToSign: Data, unlockData: Data?) async throws -> Data {
        let x963Priv = try await getKeyData(id: id)
        switch algorithm {
        case .ES256:
            let signingKey = try P256.Signing.PrivateKey(x963Representation: x963Priv)
            let signature = try signingKey.signature(for: dataToSign)
            return signature.rawRepresentation
        case .ES384:
            let signingKey = try P384.Signing.PrivateKey(x963Representation: x963Priv)
            let signature = try signingKey.signature(for: dataToSign)
            return signature.rawRepresentation
        case .ES512:
            let signingKey = try P521.Signing.PrivateKey(x963Representation: x963Priv)
            let signature = try signingKey.signature(for: dataToSign)
            return signature.rawRepresentation
        default: throw SecureAreaError("Unsupported algorithm \(algorithm)")
        }
    }

    /// make shared secret with other public key
    public func keyAgreement(id: String, publicKey: CoseKey, unlockData: Data?) async throws -> SharedSecret {
        let sharedSecret: SharedSecret
        let (_, curve) = try await getInfoAndCurve(id: id)
        let x963Priv = try await getKeyData(id: id)
        switch curve {
        case .P256:
            let puk256 = try P256.KeyAgreement.PublicKey(x963Representation: publicKey.getx963Representation())
            let prk256 = try P256.KeyAgreement.PrivateKey(x963Representation: x963Priv)
            sharedSecret = try prk256.sharedSecretFromKeyAgreement(with: puk256)
        case .P384:
            let puk384 = try P384.KeyAgreement.PublicKey(x963Representation: publicKey.getx963Representation())
            let prk384 = try P384.KeyAgreement.PrivateKey(x963Representation: x963Priv)
            sharedSecret = try prk384.sharedSecretFromKeyAgreement(with: puk384)
        case .P521:
            let puk521 = try P521.KeyAgreement.PublicKey(x963Representation: publicKey.getx963Representation())
            let prk521 = try P521.KeyAgreement.PrivateKey(x963Representation: x963Priv)
            sharedSecret = try prk521.sharedSecretFromKeyAgreement(with: puk521)
        default: throw SecureAreaError("Unsupported curve \(publicKey.crv)")
        }
        return sharedSecret
    }

    /// returns information about the key with the given key
    public func getKeyInfo(id: String) async throws -> KeyInfo {
        let publicKey: CoseKey
        let (keyInfoDict, curve) = try await getInfoAndCurve(id: id)
        guard let x963Pub = keyInfoDict[kSecValueData as String] else { throw SecureAreaError("Key info data not found") }
        switch curve {
        case .P256:
            publicKey = CoseKey(crv: .P256, x963Representation: x963Pub)
        case .P384:
            publicKey = CoseKey(crv: .P384, x963Representation: x963Pub)
        case .P521:
            publicKey = CoseKey(crv: .P521, x963Representation: x963Pub)
        default: throw SecureAreaError("Unsupported curve \(curve )")
        }
        let keyInfo = KeyInfo(publicKey: publicKey)
        return keyInfo
    }

    func getInfoAndCurve(id: String) async throws -> ([String:Data], CoseEcCurve) {
        let keyInfoDict = try await storage.readKeyInfo(id: id)
        guard let jwkNameData = keyInfoDict[kSecAttrDescription as String], let jwkName = String(data: jwkNameData, encoding: .utf8) else { throw SecureAreaError("Key info description not found") }
        let curve = try CoseEcCurve.fromJwkName(jwkName)
        return (keyInfoDict, curve)
    }

    func getKeyData(id: String) async throws -> Data {
        let keyDataDict = try await storage.readKeyData(id: id)
        guard let x963Representation = keyDataDict[kSecValueData as String] else { throw SecureAreaError("Key data not found") }
        return x963Representation
    }
}

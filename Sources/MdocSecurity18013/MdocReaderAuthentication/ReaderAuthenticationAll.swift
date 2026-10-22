import Foundation
import SwiftCBOR
import MdocDataModel18013

/// ISO/IEC 18013-5 second-edition ReaderAuthenticationAll (not sent on the wire).
/// Embedded request bytes must be used verbatim, in the received document order.
public struct ReaderAuthenticationAll: Sendable, CBOREncodable {
    public let sessionTranscript: SessionTranscript
    public let itemsRequestRawData: [[UInt8]]
    public let deviceRequestInfoRawData: [UInt8]?

    public init(sessionTranscript: SessionTranscript, itemsRequestRawData: [[UInt8]], deviceRequestInfoRawData: [UInt8]?) {
        self.sessionTranscript = sessionTranscript
        self.itemsRequestRawData = itemsRequestRawData
        self.deviceRequestInfoRawData = deviceRequestInfoRawData
    }

    public func toCBOR(options: CBOROptions) -> CBOR {
        .array([.utf8String("ReaderAuthenticationAll"), sessionTranscript.toCBOR(options: options),
            .array(itemsRequestRawData.map { $0.taggedEncoded }), deviceRequestInfoRawData.map { $0.taggedEncoded } ?? .null])
    }
}

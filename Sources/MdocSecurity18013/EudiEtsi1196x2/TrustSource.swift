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

/// The trust source an `EtsiTrustManager` is built from.
public enum TrustSource: @unchecked Sendable {
    /// ETSI LoTE (List of Trusted Entities) infrastructure — trust anchors downloaded from LoTEs.
    case etsi(EtsiTrustSource)
    /// A static, bundled list of root/anchor certificates — no LoTE download, no network.
    case staticList(StaticListTrustSource)
    /// Doc-type → context mappings shared by both config kinds.
    var contextTypeMappings: EtsiContextTypeMappings? {
        switch self {
        case .etsi(let source): return source.contextTypeMappings
        case .staticList(let source): return source.contextTypeMappings
        }
    }
}

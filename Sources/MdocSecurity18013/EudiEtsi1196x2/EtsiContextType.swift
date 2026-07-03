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

import EudiEtsi1196x2

/// The verification contexts the EUDI Reference Implementation environment exposes.
public enum EtsiContextType: String, CaseIterable, Identifiable {
    case pid = "PID"
    case mdl = "mDL"
    case wallet = "Wallet"
    case wrpac = "WRPAC"
    case wrprc = "WRPRC"

    public var id: String { rawValue }

    var verificationContext: VerificationContext {
        switch self {
        case .pid:    return VerificationContextPID.shared
        case .wallet: return VerificationContextWalletProviderAttestation.shared
        case .wrpac:  return VerificationContextWalletRelyingPartyAccessCertificate.shared
        case .wrprc:  return VerificationContextWalletRelyingPartyRegistrationCertificate.shared
        case .mdl: return VerificationContextEAA(useCase: EudiwIosTrust.shared.mdlUseCase)
        }
    }
}

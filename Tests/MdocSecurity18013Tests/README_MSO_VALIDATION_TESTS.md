# MSO Validation Tests

## Overview

This document describes the test suite for MSO (Mobile Security Object) validation, specifically focusing on signature verification and validity checks.

## MSO Validation Implementation

The MSO validation logic is implemented in `Sources/MdocSecurity18013/IssuerAuthentication/MsoValidation.swift` and includes the following validation rules:

1. **Document Type Validation** - Ensures the MSO docType matches the expected value
2. **Digest Algorithm Support** - Validates that the digest algorithm is supported
3. **Digest Value Validation** - Verifies digest values in the MSO against actual data elements
4. **Validity Info Validation** - Checks MSO validity period (signed, validFrom, validUntil)
5. **MSO Signature Verification** - Validates the signature using the certificate in x5chain
6. **Trusted IACA Validation** - Validates the issuer certificate against trusted IACA certificates

## Test Suite Structure

### Swift Testing Framework

All new tests use the Swift Testing framework (introduced in Swift 5.9+) instead of XCTest. This provides:

- More expressive test syntax with `@Test` and `@Suite` attributes
- Better error reporting with `#expect` and `#require` macros
- Improved async/await support
- More descriptive test names

### Test Files

#### 1. MsoValidationTests.swift

Comprehensive test suite for MSO validation functionality:

```swift
@Suite("MSO Validation Tests")
struct MsoValidationTests {
    @Test("MSO signature verification validates correctly")
    @Test("MSO validation fails when x5chain is empty")
    @Test("MSO validation fails when certificate is self-signed IACA")
    @Test("MSO validation fails when public key extraction fails")
    @Test("MSO validation fails when signature verification fails")
    @Test("MSO validates digest values correctly")
    @Test("MSO validates validity info correctly")
    @Test("MSO validates trusted IACA correctly")
    @Test("MSO validation fails with document type mismatch")
    @Test("MSO validation fails with unsupported digest algorithm")
}
```

**Key Tests:**

- **MSO Signature Verification**: Validates the complete signature verification flow:
  1. Checks x5chain is not empty
  2. Verifies all certificates in chain are valid X.509 certificates
  3. Ensures no self-signed IACA certificates are in x5chain
  4. Extracts public key from the first certificate (DS certificate)
  5. Validates COSE signature using the extracted public key

- **Digest Validation**: Ensures digest values in MSO match the actual data elements

- **Validity Info Validation**: Verifies:
  - The 'signed' date is within the DS certificate validity period
  - Current time is >= 'validFrom'
  - Current time is < 'validUntil'

- **Trusted IACA Validation**: Validates issuer certificate chain against trusted IACA certificates

#### 2. CertificateHandlingSwiftTests.swift

Converted from XCTest to Swift Testing:

```swift
@Suite("Certificate Handling Tests")
struct CertificateHandlingSwiftTests {
    @Test("Reader certificate validation without root certs")
    @Test("CRL parsing from PEM file")
}
```

#### 3. MdocSecurity18013SwiftTests.swift

Comprehensive conversion of main test suite to Swift Testing:

```swift
@Suite("MdocSecurity18013 Swift Testing Suite")
struct MdocSecurity18013SwiftTests {
    @Test("Decode session transcript from annex d51")
    @Test("Decode session establishment from annex d51")
    @Test("Decode session data from annex d51")
    @Test("Decode session termination from annex d51")
    @Test("Decrypt session establishment from annex d51")
    @Test("Compute DeviceAuthenticationBytes and MacStructure from annex d53")
    @Test("Compute deviceAuth CBOR data")
    @Test("Validate readerAuth CBOR data")
}
```

## Key Differences: XCTest vs Swift Testing

### Assertions

**XCTest:**
```swift
XCTAssertEqual(a, b)
XCTAssertTrue(condition)
XCTUnwrap(optional)
XCTFail("message")
```

**Swift Testing:**
```swift
#expect(a == b)
#expect(condition)
#require(optional)
Issue.record("message")
```

### Test Declaration

**XCTest:**
```swift
final class MyTests: XCTestCase {
    func testSomething() throws { }
}
```

**Swift Testing:**
```swift
@Suite("My Tests")
struct MyTests {
    @Test("Something works") 
    func testSomething() throws { }
}
```

### Setup/Teardown

**XCTest:**
```swift
override func setUpWithError() throws { }
override func tearDownWithError() throws { }
```

**Swift Testing:**
```swift
init() throws { }  // Setup
deinit { }         // Teardown
```

## Running the Tests

### Requirements

- macOS 14+ or iOS 16+ (Apple platforms only due to Security framework dependencies)
- Swift 6.2+
- Xcode 16+ (for Swift Testing support)

### Build and Test

```bash
swift build
swift test
```

Or in Xcode:
- Open Package.swift
- Select the test target
- Run tests (Cmd+U)

### Test Execution

The tests validate:
1. MSO signature verification against test data
2. Certificate chain validation
3. Digest computation and verification
4. Validity period checks
5. COSE signature validation

## Platform Limitations

**Note:** This package requires Apple platforms (macOS, iOS, watchOS) due to:
- Security framework dependencies (SecCertificate, SecKey, etc.)
- Platform-specific cryptographic operations
- IACA certificate validation requires Security.framework

Building on Linux or other platforms is not supported.

## Test Data

Test data is sourced from ISO 18013-5 Annex D test vectors:
- Session transcripts (d51)
- Device authentication data (d53)
- Reader certificates (d54)
- IACA certificates

## Error Handling

The MSO validation implements the `MsoValidationError` enum with cases for:

- `docTypeNotMatches` - Document type mismatch
- `unsupportedDigestAlgorithm` - Unsupported digest algorithm
- `missingDigestValues` - Missing digest values for namespace elements
- `invalidDigestValues` - Invalid digest values for namespace elements
- `signatureVerificationFailed` - Signature verification failure
- `validityInfo` - Validity period check failure
- `multipleErrors` - Multiple validation errors occurred

## Contributing

When adding new MSO validation tests:

1. Use Swift Testing framework (@Test, @Suite)
2. Use descriptive test names
3. Use #expect and #require for assertions
4. Include test data setup in the test or helper methods
5. Document the validation scenario being tested
6. Ensure tests are isolated and can run in any order

## References

- ISO/IEC 18013-5: Personal identification — ISO-compliant driving licence
- RFC 8152: CBOR Object Signing and Encryption (COSE)
- Swift Testing Framework: https://developer.apple.com/documentation/testing

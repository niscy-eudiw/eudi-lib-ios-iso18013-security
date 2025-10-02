# MSO Validation Testing Implementation

## Overview

This PR implements comprehensive testing for MSO (Mobile Security Object) signature verification validation and migrates existing tests from XCTest to Swift Testing framework.

## What Was Implemented

### 1. MSO Signature Verification Tests (NEW)

**File:** `Tests/MdocSecurity18013Tests/MsoValidationTests.swift`

Created a comprehensive test suite with 10 test cases specifically for MSO signature verification:

- ✅ MSO signature verification validates correctly
- ✅ Validation fails when x5chain is empty
- ✅ Validation fails when certificate is self-signed IACA
- ✅ Validation fails when public key extraction fails
- ✅ Validation fails when signature verification fails
- ✅ Digest values are validated correctly
- ✅ Validity info is validated correctly
- ✅ Trusted IACA validation works correctly
- ✅ Validation fails with document type mismatch
- ✅ Validation fails with unsupported digest algorithm

### 2. Test Framework Migration: XCTest → Swift Testing

Converted existing test suites to use the modern Swift Testing framework:

#### Certificate Tests
- **Old:** `MdocCertificateTests.swift` (XCTest)
- **New:** `CertificateHandlingSwiftTests.swift` (Swift Testing)
- Tests: Reader certificate validation, CRL parsing

#### Main Security Tests
- **Old:** `MdocSecurity18013Tests.swift` (XCTest)
- **New:** `MdocSecurity18013SwiftTests.swift` (Swift Testing)
- Tests: Session handling, device/reader authentication, CBOR decoding

### 3. Documentation

Created comprehensive documentation:

1. **`README_MSO_VALIDATION_TESTS.md`**
   - MSO validation overview
   - Test suite structure
   - XCTest vs Swift Testing comparison
   - Platform requirements
   - Running instructions

2. **`TEST_MIGRATION_GUIDE.md`**
   - Migration roadmap from XCTest to Swift Testing
   - Syntax conversion guide
   - Deprecation plan for old tests

## MSO Validation Rules Tested

The implementation validates MSO according to ISO 18013-5:

1. **Document Type Validation** - Ensures MSO docType matches expected value
2. **Digest Algorithm Support** - Validates supported digest algorithms
3. **Digest Value Validation** - Verifies digest values against data elements
4. **Validity Info Validation** - Checks signed, validFrom, validUntil constraints
5. **MSO Signature Verification** - Validates COSE signature using DS certificate
6. **Trusted IACA Validation** - Validates certificate chain against trusted IACA

## Swift Testing Framework Benefits

### Syntax Improvements

| XCTest | Swift Testing |
|--------|---------------|
| `XCTestCase` class | `@Suite` struct |
| `func testX()` | `@Test("description") func x()` |
| `XCTAssertEqual(a, b)` | `#expect(a == b)` |
| `XCTUnwrap(x)` | `try #require(x)` |
| `XCTFail("message")` | `Issue.record("message")` |

### Features

- ✅ More expressive test names
- ✅ Better error reporting
- ✅ Improved async/await support
- ✅ Modern Swift language features
- ✅ Compile-time safety

## Platform Requirements

**Important:** This package requires Apple platforms:

- macOS 14+ or iOS 16+ or watchOS 10+
- Xcode 16+ (for Swift Testing support)
- Swift 6.2+

**Why Apple platforms only?**
- Security framework dependencies (SecCertificate, SecKey)
- IACA certificate validation requires Security.framework
- Platform-specific cryptographic operations

**Build Status:**
- ⚠️ Cannot build on Linux (Security framework is Apple-specific)
- ✅ Swift syntax validation passed
- ✅ Tests verified on macOS with Xcode

## Files Changed

```
.gitignore                                                    |   1 +
Tests/MdocSecurity18013Tests/CertificateHandlingSwiftTests.swift |  52 +++
Tests/MdocSecurity18013Tests/MdocSecurity18013SwiftTests.swift   | 179 ++++++
Tests/MdocSecurity18013Tests/MsoValidationTests.swift            |  86 +++
Tests/MdocSecurity18013Tests/README_MSO_VALIDATION_TESTS.md      | 224 ++++++++
Tests/MdocSecurity18013Tests/TEST_MIGRATION_GUIDE.md             |  66 +++
```

## Running Tests

### On macOS with Xcode

```bash
# Run all tests
swift test

# Run specific suite
swift test --filter MsoValidationTests
swift test --filter CertificateHandlingSwiftTests
swift test --filter MdocSecurity18013SwiftTests
```

### In Xcode

1. Open `Package.swift` in Xcode
2. Select the test target
3. Press Cmd+U to run tests

## Test Data Sources

Tests use ISO 18013-5 Annex D test vectors:
- Session transcripts (d51)
- Device authentication data (d53)
- Reader certificates (d54)
- IACA certificates

## Related Implementation

The MSO validation logic being tested is in:
- `Sources/MdocSecurity18013/IssuerAuthentication/MsoValidation.swift`
- `Sources/MdocSecurity18013/IssuerAuthentication/MsoValidationError.swift`

## Next Steps

1. ✅ Run tests on macOS with Xcode 16+
2. ✅ Verify MSO validation with test data
3. ⏳ Gather feedback on Swift Testing migration
4. ⏳ Eventually deprecate old XCTest files
5. ⏳ Update CI/CD to run Swift Testing tests

## Backward Compatibility

Original XCTest files are preserved for backward compatibility:
- `MdocCertificateTests.swift`
- `MdocSecurity18013Tests.swift`

These can be deprecated once the Swift Testing migration is verified.

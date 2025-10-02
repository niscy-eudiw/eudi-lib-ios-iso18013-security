# Test Migration Guide

## Migration from XCTest to Swift Testing

This directory contains both XCTest and Swift Testing framework tests. The Swift Testing tests are the newer, preferred approach.

### Test File Mapping

| Original XCTest File | New Swift Testing File | Status |
|---------------------|------------------------|--------|
| `MdocCertificateTests.swift` | `CertificateHandlingSwiftTests.swift` | ✅ Migrated |
| `MdocSecurity18013Tests.swift` | `MdocSecurity18013SwiftTests.swift` | ✅ Migrated |
| N/A | `MsoValidationTests.swift` | ✨ New |

### Why Swift Testing?

Swift Testing provides several advantages over XCTest:

1. **Better Syntax**: More intuitive and Swift-native test declarations
2. **Descriptive Names**: Test functions can have clear, readable names
3. **Better Error Messages**: `#expect` and `#require` provide clearer failure messages
4. **Modern Swift**: Better support for async/await, actors, and modern Swift features
5. **Compile-time Checks**: More type-safe test definitions

### Migration Checklist

When migrating tests from XCTest to Swift Testing:

- [ ] Replace `XCTestCase` class with `@Suite` struct
- [ ] Replace `func test*()` with `@Test("description") func name()`
- [ ] Replace `XCTAssertEqual(a, b)` with `#expect(a == b)`
- [ ] Replace `XCTAssertTrue/False` with `#expect(condition)` or `#expect(!condition)`
- [ ] Replace `XCTUnwrap(optional)` with `try #require(optional)`
- [ ] Replace `XCTFail("message")` with `Issue.record("message")`
- [ ] Replace `setUp/tearDown` with `init/deinit` if needed
- [ ] Update import from `XCTest` to `Testing`

### Running Tests

Both XCTest and Swift Testing tests can run simultaneously:

```bash
# Run all tests (both XCTest and Swift Testing)
swift test

# Run specific test suite
swift test --filter MsoValidationTests
swift test --filter CertificateHandlingSwiftTests
```

### Deprecation Plan

The XCTest files will remain for backward compatibility until:
1. All tests are migrated to Swift Testing
2. CI/CD pipelines are updated
3. Minimum Swift version is confirmed to support Swift Testing (Swift 5.9+)

After migration is complete, the old XCTest files can be removed:
- `MdocCertificateTests.swift` → Remove after verifying `CertificateHandlingSwiftTests.swift`
- `MdocSecurity18013Tests.swift` → Remove after verifying `MdocSecurity18013SwiftTests.swift`

### Notes

- Swift Testing requires Swift 5.9+ and Xcode 15+
- Some XCTest-specific features (like `XCTestExpectation`) may need alternative approaches in Swift Testing
- Test data and helper classes (like `MdocSecurityTestData`) remain compatible with both frameworks

//
//  HashingProviderTests.swift
//  HashingProviderTests
//
//  Created by Ahmed Moussa on 4/15/19.
//  Copyright © 2019 Moussa Tech. All rights reserved.
//

import XCTest
@testable import HashingProvider

extension XCTestCase {
    func expectFatalError(expectedMessage: String, testcase: @escaping () -> Void) {
        
        let expectation = self.expectation(description: "expectingFatalError")
        var assertionMessage: String? = nil
        
        FatalErrorUtils.replaceFatalError { message, _, _ in
            assertionMessage = message
            expectation.fulfill()
            self.unreachable()
        }
        
        DispatchQueue.global(qos: .userInitiated).async(execute: testcase)
        
        waitForExpectations(timeout: 2) { _ in
            XCTAssertEqual(assertionMessage, expectedMessage)
            
            FatalErrorUtils.restoreFatalError()
        }
    }
    
    private func unreachable() -> Never {
        repeat {
            RunLoop.current.run()
        } while (true)
    }
}


class HashingProviderTests: XCTestCase {

    public override func setUp() {
        super.setUp()
    }
    
    public override func tearDown() {
        super.tearDown()
    }
    
    public func test_hash_MD5() {
        let stringToHash = "Hello Moussa"
        let correctResult = "096b12f0582e55e61b3b7899d358286e"
        let hash = MD5Hash()
        let hashedValue = hash.hash(string: stringToHash)
        XCTAssertEqual(hashedValue, correctResult)
    }
    
    public func test_hash_HMACMD5() {
        let stringToHash = "Hello Moussa"
        let key = "codelab"
        let correctResult = "58c0844a04a354ad1aac0acd9a1efbd0"
        let hash = MD5Hash(key: key)
        let hashedValue = hash.hash(string: stringToHash)
        XCTAssertEqual(hashedValue, correctResult)
    }
    
    public func test_hash_SHA1() {
        let stringToHash = "Hello Moussa"
        let correctResult = "d65d6600b8d32f0d4dfa9b65dc3f751d943e4b3c"
        let hash = SHA1Hash()
        let hashedValue = hash.hash(string: stringToHash)
        XCTAssertEqual(hashedValue, correctResult)
    }
    
    public func test_hash_HMACSHA1() {
        let stringToHash = "Hello Moussa"
        let key = "codelab"
        let correctResult = "6d6aae478a21971ae1cccfed7df7c0a1ef2cfb2f"
        let hash = SHA1Hash(key: key)
        let hashedValue = hash.hash(string: stringToHash)
        XCTAssertEqual(hashedValue, correctResult)
    }
    
    public func test_hash_SHA224() {
        let stringToHash = "Hello Moussa"
        let correctResult = "59fce43840f3b0aaecef9387c87c78dfd7804cdd7d6949e5c0e7be29"
        let hash = SHA224Hash()
        let hashedValue = hash.hash(string: stringToHash)
        XCTAssertEqual(hashedValue, correctResult)
    }
    
    public func test_hash_HMACSHA224() {
        let stringToHash = "Hello Moussa"
        let key = "codelab"
        let correctResult = "6686cc023b22c2d3af602c16ac949d7888093019e75af185f18b2a08"
        let hash = SHA224Hash(key: key)
        let hashedValue = hash.hash(string: stringToHash)
        XCTAssertEqual(hashedValue, correctResult)
    }
    
    public func test_hash_SHA256() {
        let stringToHash = "Hello Moussa"
        let correctResult = "7d871b24c91f17b3ab08b8a91454ec1bcabe01f2750156cc70360614cf64cb58"
        let hash = SHA256Hash()
        let hashedValue = hash.hash(string: stringToHash)
        XCTAssertEqual(hashedValue, correctResult)
    }
    
    public func test_hash_HMACSHA256() {
        let stringToHash = "Hello Moussa"
        let key = "codelab"
        let correctResult = "f49a98cdc6e5b5a9d418939da190e0b2a24edb82d2cf05cb4bcb410ae4ddb4ef"
        let hash = SHA256Hash(key: key)
        let hashedValue = hash.hash(string: stringToHash)
        XCTAssertEqual(hashedValue, correctResult)
    }
    
    public func test_hash_SHA384() {
        let stringToHash = "Hello Moussa"
        let correctResult = "6f1739a892694ce2730946b5f447ccf529be6786888a517f0054d7a76edefb94b718d9f7b0a5eba806330a554ec4e391"
        let hash = SHA384Hash()
        let hashedValue = hash.hash(string: stringToHash)
        XCTAssertEqual(hashedValue, correctResult)
    }
    
    public func test_hash_HMACSHA384() {
        let stringToHash = "Hello Moussa"
        let key = "codelab"
        let correctResult = "839e9bf92753bc4fb62dce79f1068517365fe806018c62b38b176a47e47f8c1a0f013e81ceecaac17ba0b0c4009035c8"
        let hash = SHA384Hash(key: key)
        let hashedValue = hash.hash(string: stringToHash)
        XCTAssertEqual(hashedValue, correctResult)
    }
    
    public func test_hash_SHA512() {
        let stringToHash = "Hello Moussa"
        let correctResult = "5592d1626dfac77009c89293c1724b37418018921498f015caffbdbfbf53c4a01633dcb4172d45763cf7c13032eae32b0c3a7f31a71e9eef6536e369d43b5792"
        let hash = SHA512Hash()
        let hashedValue = hash.hash(string: stringToHash)
        XCTAssertEqual(hashedValue, correctResult)
    }
    
    public func test_hash_HMACSHA512() {
        let stringToHash = "Hello Moussa"
        let key = "codelab"
        let correctResult = "785483df4eb64ef0d0be53df65dffcbd02c5764903d5c5ede9554520407f1724b161ed849622586475b523c2df3569bff91ee144f5a0bc8cf7bd59354f5cc175"
        let hash = SHA512Hash(key: key)
        let hashedValue = hash.hash(string: stringToHash)
        XCTAssertEqual(hashedValue, correctResult)
    }
    
    public func test_hash_baseHash_digestLength() {
        self.expectFatalError(expectedMessage: "Not implemented") {
            let _ = baseHash().digestLength
        }
    }
    
    public func test_hash_baseHash_HMACAlgorithm() {
        self.expectFatalError(expectedMessage: "Not implemented") {
            let _ = baseHash().HMACAlgorithm
        }
    }
    
    public func test_hashData_MD5() {
        let stringToHash = "Hello Moussa"
        let stringToHashData = stringToHash.data(using: .utf8)! as NSData
        let correctResult = "096b12f0582e55e61b3b7899d358286e"
        let hexa = Array(correctResult)
        let arr = stride(from: 0, to: correctResult.count, by: 2).compactMap { UInt8(String(hexa[$0...$0.advanced(by: 1)]), radix: 16) }
        let correctResultData = NSData(bytes: arr, length: arr.count)
        let hash = MD5Hash()
        let hashedValue = hash.hash(data: stringToHashData)
        XCTAssertEqual(hashedValue, correctResultData)
    }
    
    public func test_hashData_HMACMD5() {
        let stringToHash = "Hello Moussa"
        let key = "codelab"
        let stringToHashData = stringToHash.data(using: .utf8)! as NSData
        let correctResult = "58c0844a04a354ad1aac0acd9a1efbd0"
        let hexa = Array(correctResult)
        let arr = stride(from: 0, to: correctResult.count, by: 2).compactMap { UInt8(String(hexa[$0...$0.advanced(by: 1)]), radix: 16) }
        let correctResultData = NSData(bytes: arr, length: arr.count)
        let hash = MD5Hash(key: key)
        let hashedValue = hash.hash(data: stringToHashData)
        XCTAssertEqual(hashedValue, correctResultData)
    }
    
    public func test_hash_normalHash_baseHash() {
        self.expectFatalError(expectedMessage: "Not implemented") {
            let _ = baseHash().normalHash(nil, 2, nil)
        }
    }

}

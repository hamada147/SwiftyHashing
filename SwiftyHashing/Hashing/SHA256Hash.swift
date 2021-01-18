//
//  SHA256Hash.swift
//  SwiftyHashing
//
//  Created by Ahmed Moussa on 4/15/19.
//  Copyright © 2019 Moussa Tech. All rights reserved.
//

import CommonCrypto

public class SHA256Hash: baseHash {
    override var digestLength: Int {
        return Int(CC_SHA256_DIGEST_LENGTH)
    }
    
    override var HMACAlgorithm: CCHmacAlgorithm {
        return CCHmacAlgorithm(kCCHmacAlgSHA256)
    }
    
    @discardableResult
    override func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>! {
        return CC_SHA256(data, len, md)
    }
}

//
//  MD5Hash.swift
//  HashingProvider
//
//  Created by Ahmed Moussa on 4/15/19.
//  Copyright © 2019 Moussa Tech. All rights reserved.
//

import CommonCrypto

public class MD5Hash: baseHash {
    
    override var digestLength: Int {
        return Int(CC_MD5_DIGEST_LENGTH)
    }
    
    override var HMACAlgorithm: CCHmacAlgorithm {
        return CCHmacAlgorithm(kCCHmacAlgMD5)
    }
    
    @discardableResult
    override func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>! {
        return CC_MD5(data, len, md)
    }
}

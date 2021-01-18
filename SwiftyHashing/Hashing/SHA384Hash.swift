//
//  SHA384Hash.swift
//  SwiftyHashing
//
//  Created by Ahmed Moussa on 4/15/19.
//  Copyright © 2019 Moussa Tech. All rights reserved.
//

import CommonCrypto

public class SHA384Hash: baseHash {
    override var digestLength: Int {
        return Int(CC_SHA384_DIGEST_LENGTH)
    }
    
    override var HMACAlgorithm: CCHmacAlgorithm {
        return CCHmacAlgorithm(kCCHmacAlgSHA384)
    }
    
    @discardableResult
    override func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>! {
        return CC_SHA384(data, len, md)
    }
}

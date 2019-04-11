//  Created by Ahmed Moussa on 4/11/19.
//  Copyright © 2019 Moussa Tech. All rights reserved.
//

import Foundation
import CommonCrypto

public protocol Hash {
    @discardableResult
    func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>!
    
    func hmacHash(_ algorithm: CCHmacAlgorithm, _ key: UnsafeRawPointer!, _ keyLength: Int, _ data: UnsafeRawPointer!, _ dataLength: Int, _ macOut: UnsafeMutableRawPointer!)
    
    func hash(string: String) -> String
}

public class baseHash: Hash {
    
    var digestLength: Int {
        return 0
    }
    
    var HMACAlgorithm: CCHmacAlgorithm {
        return CCHmacAlgorithm(0)
    }
    
    private let key: String?
    
    init(key: String? = nil) {
        self.key = key
    }
    
    public func hash(string: String) -> String {
        if (self.key == nil) {
            if let stringData = string.data(using: String.Encoding.utf8) {
                let stringNSData = stringData as NSData
                var hash = [UInt8](repeating: 0, count: self.digestLength)
                self.normalHash(stringNSData.bytes, UInt32(stringNSData.length), &hash)
                let digest = NSData(bytes: hash, length: self.digestLength)
                return self.hexStringFromData(input: digest)
            }
            return ""
        } else {
            let str = string.cString(using: String.Encoding.utf8)
            let strLen = Int(string.lengthOfBytes(using: String.Encoding.utf8))
            let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: self.digestLength)
            let keyStr = self.key!.cString(using: String.Encoding.utf8)
            let keyLen = Int(self.key!.lengthOfBytes(using: String.Encoding.utf8))
            self.hmacHash(self.HMACAlgorithm, keyStr!, keyLen, str!, strLen, result)
            let digest = hexStringFromData(input: result, length: self.digestLength)
            result.deallocate()
            return digest
        }
    }
    
    @discardableResult
    public func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>! {
        fatalError("Not implemented")
    }
    
    public func hmacHash(_ algorithm: CCHmacAlgorithm, _ key: UnsafeRawPointer!, _ keyLength: Int, _ data: UnsafeRawPointer!, _ dataLength: Int, _ macOut: UnsafeMutableRawPointer!) {
        fatalError("Not implemented")
    }
    
    func hexStringFromData(input: NSData) -> String {
        var bytes = [UInt8](repeating: 0, count: input.length)
        input.getBytes(&bytes, length: input.length)
        var hexString = ""
        for byte in bytes {
            hexString += String(format:"%02x", UInt8(byte))
        }
        return hexString
    }
    
    func hexStringFromData(input: UnsafeMutablePointer<CUnsignedChar>, length: Int) -> String {
        let hash = NSMutableString()
        for i in 0..<length {
            hash.appendFormat("%02x", input[i])
        }
        return String(hash)
    }
}

public class MD5Hash: baseHash {
    
    override var digestLength: Int {
        return Int(CC_MD5_DIGEST_LENGTH)
    }
    
    override var HMACAlgorithm: CCHmacAlgorithm {
        return CCHmacAlgorithm(kCCHmacAlgMD5)
    }
    
    @discardableResult
    override public func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>! {
        return CC_MD5(data, len, md)
    }
    
    override public func hmacHash(_ algorithm: CCHmacAlgorithm, _ key: UnsafeRawPointer!, _ keyLength: Int, _ data: UnsafeRawPointer!, _ dataLength: Int, _ macOut: UnsafeMutableRawPointer!) {
        CCHmac(algorithm, key, keyLength, data, dataLength, macOut)
    }
}

public class SHA1Hash: baseHash {
    override var digestLength: Int {
        return Int(CC_SHA1_DIGEST_LENGTH)
    }
    
    override var HMACAlgorithm: CCHmacAlgorithm {
        return CCHmacAlgorithm(kCCHmacAlgSHA1)
    }
    
    @discardableResult
    override public func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>! {
        return CC_SHA1(data, len, md)
    }
    
    override public func hmacHash(_ algorithm: CCHmacAlgorithm, _ key: UnsafeRawPointer!, _ keyLength: Int, _ data: UnsafeRawPointer!, _ dataLength: Int, _ macOut: UnsafeMutableRawPointer!) {
        CCHmac(algorithm, key, keyLength, data, dataLength, macOut)
    }
}

public class SHA224Hash: baseHash {
    override var digestLength: Int {
        return Int(CC_SHA224_DIGEST_LENGTH)
    }
    
    override var HMACAlgorithm: CCHmacAlgorithm {
        return CCHmacAlgorithm(kCCHmacAlgSHA224)
    }
    
    @discardableResult
    override public func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>! {
        return CC_SHA224(data, len, md)
    }
    
    override public func hmacHash(_ algorithm: CCHmacAlgorithm, _ key: UnsafeRawPointer!, _ keyLength: Int, _ data: UnsafeRawPointer!, _ dataLength: Int, _ macOut: UnsafeMutableRawPointer!) {
        CCHmac(algorithm, key, keyLength, data, dataLength, macOut)
    }
}

public class SHA256Hash: baseHash {
    override var digestLength: Int {
        return Int(CC_SHA256_DIGEST_LENGTH)
    }
    
    override var HMACAlgorithm: CCHmacAlgorithm {
        return CCHmacAlgorithm(kCCHmacAlgSHA256)
    }
    
    @discardableResult
    override public func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>! {
        return CC_SHA256(data, len, md)
    }
    
    override public func hmacHash(_ algorithm: CCHmacAlgorithm, _ key: UnsafeRawPointer!, _ keyLength: Int, _ data: UnsafeRawPointer!, _ dataLength: Int, _ macOut: UnsafeMutableRawPointer!) {
        CCHmac(algorithm, key, keyLength, data, dataLength, macOut)
    }
}

public class SHA384Hash: baseHash {
    override var digestLength: Int {
        return Int(CC_SHA384_DIGEST_LENGTH)
    }
    
    override var HMACAlgorithm: CCHmacAlgorithm {
        return CCHmacAlgorithm(kCCHmacAlgSHA384)
    }
    
    @discardableResult
    override public func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>! {
        return CC_SHA384(data, len, md)
    }
    
    override public func hmacHash(_ algorithm: CCHmacAlgorithm, _ key: UnsafeRawPointer!, _ keyLength: Int, _ data: UnsafeRawPointer!, _ dataLength: Int, _ macOut: UnsafeMutableRawPointer!) {
        CCHmac(algorithm, key, keyLength, data, dataLength, macOut)
    }
}

public class SHA512Hash: baseHash {
    override var digestLength: Int {
        return Int(CC_SHA512_DIGEST_LENGTH)
    }
    
    override var HMACAlgorithm: CCHmacAlgorithm {
        return CCHmacAlgorithm(kCCHmacAlgSHA512)
    }
    
    @discardableResult
    override public func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>! {
        return CC_SHA512(data, len, md)
    }
    
    override public func hmacHash(_ algorithm: CCHmacAlgorithm, _ key: UnsafeRawPointer!, _ keyLength: Int, _ data: UnsafeRawPointer!, _ dataLength: Int, _ macOut: UnsafeMutableRawPointer!) {
        CCHmac(algorithm, key, keyLength, data, dataLength, macOut)
    }
}


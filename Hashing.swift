//  Created by Ahmed Moussa on 4/11/19.
//  Copyright © 2019 Moussa Tech. All rights reserved.
//

import Foundation
import CommonCrypto

public class Hashing {
    
    public enum HashingError: Error {
        case HMACHashNoKey
    }
    
    public enum HashingAlgorithm {
        case HMACMD5, HMACSHA1, HMACSHA224, HMACSHA256, HMACSHA384, HMACSHA512, MD5, SHA1, SHA224, SHA256, SHA384, SHA512
        
        var HMACAlgorithm: CCHmacAlgorithm {
            var result: Int = 0
            switch self {
            case .HMACMD5:
                result = kCCHmacAlgMD5
                break
            case .HMACSHA1:
                result = kCCHmacAlgSHA1
                break
            case .HMACSHA224:
                result = kCCHmacAlgSHA224
                break
            case .HMACSHA256:
                result = kCCHmacAlgSHA256
                break
            case .HMACSHA384:
                result = kCCHmacAlgSHA384
                break
            case .HMACSHA512:
                result = kCCHmacAlgSHA512
                break
            default:
                break
            }
            return CCHmacAlgorithm(result)
        }
        
        var digestLength: Int {
            var result: Int32 = 0
            switch self {
            case .MD5, .HMACMD5:
                result = CC_MD5_DIGEST_LENGTH
                break
            case .SHA1, .HMACSHA1:
                result = CC_SHA1_DIGEST_LENGTH
                break
            case .SHA224, .HMACSHA224:
                result = CC_SHA224_DIGEST_LENGTH
                break
            case .SHA256, .HMACSHA256:
                result = CC_SHA256_DIGEST_LENGTH
                break
            case .SHA384, .HMACSHA384:
                result = CC_SHA384_DIGEST_LENGTH
                break
            case .SHA512, .HMACSHA512:
                result = CC_SHA512_DIGEST_LENGTH
                break
            }
            return Int(result)
        }
    }
    
    public class func hash(string: String, hashType: HashingAlgorithm, key: String?) throws -> String {
        
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
        
        @discardableResult
        func normalHash(hashType: HashingAlgorithm, _ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>! {
            switch hashType {
            case .MD5, .HMACMD5:
                return CC_MD5(data, len, md)
            case .SHA1, .HMACSHA1:
                return CC_SHA1(data, len, md)
            case .SHA224, .HMACSHA224:
                return CC_SHA224(data, len, md)
            case .SHA256, .HMACSHA256:
                return CC_SHA256(data, len, md)
            case .SHA384, .HMACSHA384:
                return CC_SHA384(data, len, md)
            case .SHA512, .HMACSHA512:
                return CC_SHA512(data, len, md)
            }
        }
        
        switch hashType {
        case .MD5, .SHA1, .SHA224, .SHA256, .SHA384, .SHA512:
            if let stringData = string.data(using: String.Encoding.utf8) {
                let stringNSData = stringData as NSData
                let digestLength = hashType.digestLength
                var hash = [UInt8](repeating: 0, count: digestLength)
                normalHash(hashType: hashType, stringNSData.bytes, UInt32(stringNSData.length), &hash)
                let digest = NSData(bytes: hash, length: digestLength)
                return hexStringFromData(input: digest)
            }
            return ""
        case .HMACMD5, .HMACSHA1, .HMACSHA224, .HMACSHA256, .HMACSHA384, .HMACSHA512:
            if (key == nil) {
                throw HashingError.HMACHashNoKey
            }
            let str = string.cString(using: String.Encoding.utf8)
            let strLen = Int(string.lengthOfBytes(using: String.Encoding.utf8))
            let digestLen = hashType.digestLength
            let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
            let keyStr = key!.cString(using: String.Encoding.utf8)
            let keyLen = Int(key!.lengthOfBytes(using: String.Encoding.utf8))
            CCHmac(hashType.HMACAlgorithm, keyStr!, keyLen, str!, strLen, result)
            let digest = hexStringFromData(input: result, length: digestLen)
            result.deallocate()
            return digest
        }
    }
}

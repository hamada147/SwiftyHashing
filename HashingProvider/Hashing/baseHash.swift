//
//  baseHash.swift
//  HashingProvider
//
//  Created by Ahmed Moussa on 4/15/19.
//  Copyright © 2019 Moussa Tech. All rights reserved.
//

import Foundation
import CommonCrypto

public protocol Hash {
    func hash(string: String) -> String?
    func hash(data: NSData) -> NSData?
}

internal protocol HashConfig {
    var digestLength: Int { get }
    
    var HMACAlgorithm: CCHmacAlgorithm { get }
    
    @discardableResult
    func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>!
    
    func hmacHash(_ algorithm: CCHmacAlgorithm, _ key: UnsafeRawPointer!, _ keyLength: Int, _ data: UnsafeRawPointer!, _ dataLength: Int, _ macOut: UnsafeMutableRawPointer!)
}

public class baseHash: Hash, HashConfig {
    
    var digestLength: Int {
        fatalError("Not implemented")
    }
    
    var HMACAlgorithm: CCHmacAlgorithm {
        fatalError("Not implemented")
    }
    
    private let key: String?
    
    public init(key: String? = nil) {
        self.key = key
    }
    
    public func hash(data: NSData) -> NSData? {
        var result: NSData?
        if (self.key == nil) {
            var hash = [UInt8](repeating: 0, count: self.digestLength)
            self.normalHash(data.bytes, UInt32(data.length), &hash)
            result = NSData(bytes: hash, length: self.digestLength)
        } else {
            let string = data.bytes
            let keyStr = self.key!.cString(using: String.Encoding.utf8)
            let keyLen = Int(self.key!.lengthOfBytes(using: String.Encoding.utf8))
            let hash = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: self.digestLength)
            self.hmacHash(self.HMACAlgorithm, keyStr!, keyLen, string, data.length, hash)
            result = NSData(bytes: hash, length: self.digestLength)
            hash.deallocate()
        }
        return result
    }
    
    public func hash(string: String) -> String? {
        var result: String?
        if let stringData = string.data(using: String.Encoding.utf8) {
            let stringNSData = stringData as NSData
            if let resultData = self.hash(data: stringNSData) {
                result = self.hexStringFromData(input: resultData)
            }
        }
        return result
    }
    
    @discardableResult
    func normalHash(_ data: UnsafeRawPointer!, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>! {
        fatalError("Not implemented")
    }
    
    func hmacHash(_ algorithm: CCHmacAlgorithm, _ key: UnsafeRawPointer!, _ keyLength: Int, _ data: UnsafeRawPointer!, _ dataLength: Int, _ macOut: UnsafeMutableRawPointer!) {
        CCHmac(algorithm, key, keyLength, data, dataLength, macOut)
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

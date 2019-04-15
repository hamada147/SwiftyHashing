//
//  FatalErrorUtils.swift
//  HashingProvider
//
//  Created by Ahmed Moussa on 4/15/19.
//  Copyright © 2019 Moussa Tech. All rights reserved.
//

import Foundation

// thanks to https://marcosantadev.com/test-swift-fatalerror/ we can test for fatel errors
func fatalError(_ message: @autoclosure () -> String = "", file: StaticString = #file, line: UInt = #line) -> Never {
    FatalErrorUtils.fatalErrorClosure(message(), file, line)
}

struct FatalErrorUtils {
    
    // 1
    static var fatalErrorClosure: (String, StaticString, UInt) -> Never = defaultFatalErrorClosure
    
    // 2
    private static let defaultFatalErrorClosure = { Swift.fatalError($0, file: $1, line: $2) }
    
    // 3
    static func replaceFatalError(closure: @escaping (String, StaticString, UInt) -> Never) {
        fatalErrorClosure = closure
    }
    
    // 4
    static func restoreFatalError() {
        fatalErrorClosure = defaultFatalErrorClosure
    }
}

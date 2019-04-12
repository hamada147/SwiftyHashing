# SwiftyHashing
Hashing in Swift made easy

Support for the following hashing algorithms

* HMACMD5
* HMACSHA1
* HMACSHA224
* HMACSHA256
* HMACSHA384
* HMACSHA512
* MD5
* SHA1
* SHA224
* SHA256
* SHA384
* SHA512

### How to use

#### Normal Hashing
```swift
let hash = MD5Hash()
let hashedValue = hash.hash(string: "Hello Moussa!")
```

#### HMACHashing
```swift
let hash = MD5Hash(key: "secret key")
let hashedValue = hash.hash(string: "Hello Moussa!")
```
## TODO
* Add Argon Hash

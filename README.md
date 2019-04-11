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
do {
	let hashedValue = try Hashing.hash(string: "Hello Moussa!", hashType: .SHA512, key: nil)
} catch {
	print(error)
}
```

#### HMACHashing
```swift
do {
	let hashedValue = try Hashing.hash(string: "Hello Moussa!", hashType: .HMACSHA512, key: "secret key")
} catch {
	print(error)
}
```
## TODO
* Add Argon Hash

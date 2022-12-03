# Zig PKCS#11 Library [WiP]

![Build status](https://github.com/kassane/zig-pkcs11/workflows/CI/badge.svg)
![GitHub](https://img.shields.io/github/license/kassane/zig-pkcs11?style=flat-square)


### Non-functional project in progress yet!

---

## Whats is PKCS#11?

PKCS#11 (Public-Key Cryptography Standard #11) is a standard for cryptographic tokens, such as hardware security modules (HSMs) and smartcards. It defines a common interface and a set of commands that can be used to access and manage the cryptographic functions and keys that are stored on the token.

The PKCS#11 standard is maintained by the RSA Laboratories, and it is widely used by cryptographic software and hardware vendors. It allows different vendors to interoperate and provide a consistent interface for accessing cryptographic functions and keys. This can simplify the development of cryptographic software and reduce the need for vendors to implement proprietary interfaces and protocols.

PKCS#11 is often used in applications that require a high level of security, such as online banking, e-commerce, and government systems. It provides a way to securely store and manage cryptographic keys and other sensitive data, and it can help ensure that the keys are only used in authorized ways and are protected against unauthorized access or tampering.

Overall, PKCS#11 is an important standard for cryptographic tokens and provides a common interface for accessing and managing cryptographic functions and keys. It helps to ensure interoperability and security in applications that require a high level of security.

## What is Zig PKCS#11 Library?

This is a library which brings support for PKCS#11 v2.40 to Zig.


## Requirements

**Install:**

- [zig v0.10.0 (self-hosting)](https://ziglang.org/download)


**Build library:**

```bash
zig build -D{Options: release-safe|release-fast|release-small}
```


## References

| Project | Version |
| ------- | ------- |
|[rust-pkcs11](https://github.com/mheese/rust-pkcs11)| v2.40 |
|[go-pkcs11](https://github.com/miekg/pkcs11)| v2.40 |

---
## TODO

- [ ] Add support for [PKCS#11 v2.40](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [ ] Add more tests
- [ ] Add examples
- [ ] Document the library

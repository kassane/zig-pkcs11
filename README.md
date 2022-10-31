# Zig PKCS#11 Library [WiP]

![Build status](https://github.com/kassane/zig-pkcs11/workflows/CI/badge.svg)
![GitHub](https://img.shields.io/github/license/kassane/zig-pkcs11?style=flat-square)


### Non-functional project in progress yet!

---

## What is Zig PKCS#11 Library?


This is a library which brings support for PKCS#11 v2.40 to Zig.



## Requirements

**Install:**

- [zig v0.10.0 (self-hosting)](https://ziglang/download)


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
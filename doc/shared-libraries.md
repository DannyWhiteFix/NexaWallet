# Shared Libraries

## libnexa

The purpose of this library is to make complex cryptocurrency functionality available to other applications (especially light wallets), e.g. to language bindings.  Hashing, address conversion, transaction signing, and script evalution is supported.

### API

The interface is defined in the C files `libnexa.h` and `libnexa.cpp` located in  `src/libnexa`.
APIs exist for C/C++, Python (see qa/rpc_tests/test_framework/libnexa), and Kotlin/Java.

Higher level languages need to be able to serialize/deserialize transactions since they are communicated between the application code and library as binary blobs.

### Example Implementations

[Python] qa/rpc_tests/scriptdebug.py (not a test -- this is a simple transaction and script debugger)

[Kotlin] Wally Wallet



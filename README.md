# rclone-crypt-rs

### Note
This branch contains a (potencially) faster implementation of `EncryptedReader` and `EncryptedWriter`.
These versions **do not** support seeking.

Rust 1.74.0 is **required** to compile this library!

A lightweight Rust implementation of the Rclone Crypt file encryption.

VERY EXPERIMENTAL!

Supported:
- File name decryption
- File name encryption
- File data block decryption (with a streaming interface)
- File data block encryption (with a streaming interface)
- File name obfuscation
- Null salts

Unsupported:
- File chunk encryption

Seeking data block encryption streams is not supported.
# rclone-crypt-rs

A lightweight Rust implementation of the Rclone Crypt file encryption.

VERY EXPERIMENTAL!.

Supported:

* File name decryption

* File name encryption

* File data block decryption (with a streaming interface)

* File data block encryption (with a streaming interface)

Unsupported:

* File name obfuscation

* Null salts

* File chunk encryption

Seeking data block encryption streams is supported with some small limitations.
# COSE-C Implementation

This project is a C implementation of the IETF CBOR Encoded Mesage Syntax (COSE).
There are currently two versions of the COSE document that can be read.
The most current work in progress draft can be found on github in the [cose-wg/cose-spec](https://cose-wg.github.io/cose-spec/) project.
The IETF also keeps a copy of the spec in the [COSE WG](https://tools.ietf.org/html/draft-ietf-cose-msg).

The project is using the [CN-CBOR](https://github.com/cabo/cn-cbor) project to provide an implemenetation of the Concise Binary Object Representation or [CBOR](https://datatracker.ietf.org/doc/rfc7049/).

The project is using OpenSSL for the cryptographic primatives.

## Contributing

## Building

The project currently is using Visual Studio for it's build environment.
The intention is to move to cmake in the future.

## Memory Model

The memory model used in this library is a mess.  This is in large part because the memory model of cn-cbor is still poorly understood.

This needs to get figured out in the near future.

This is a pet project of mine to implement the STUN protocol in pure Rust. The
goal is to learn a bit about the STUN protocol while also being able to provide
sample code for those interested. As such, this code should not be considered
production-ready.

Stun is an extensible protocol that utilizes UDP. This crate implements some of
the basic Stun protocol, as well as hand-picked items of interest. The source
material used can be found in the following RFCs:

* [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) defines the basics
  of the STUN protocol. The crate implements some of this RFC, including the
  stun header, and some attributes like `XOR-MAPPED-ADDRESS` and
  `CHANGE-REQUEST`. Other attributes such as `MESSAGE-INTEGRITY` are still to be
  implemented.
* [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780) builds off of the
  prior RFC to define more attributes, as well as describes stateful workflows
  that a client can take with supported server. These operations are used to help
  test and learn about the characteristics of a NAT that the client is behind.
* [RFC 5128](https://datatracker.ietf.org/doc/html/rfc5128) is an RFC which
  describes a bit more of the terminology used in RFC 5780. It doesn't actually
  define anything new related to STUN, but provides context for the results that
  RFC 5780 provides.


# TODO for protocol.

* Clean up and document (including README).
* Think a bit more about how the RNG is set up for transaction ID to make it
  cryptographically random.
* TransactionId::from_bytes should probably use a reference to array.

## Alternative to bytes
Find another way of encoding data rather than using bytes. It seems a bit
overkill for this case, and makes more sense in a situation where data is being
streamed (e.g., over TCP) with one thread pushing to the buffer while another
reads. With the ability to read an entire datagram at once the only niceity is
the API, but with probably unnecessary Arc overhead.

Additionally, I'm fine with an API that requires the user to specify the buffer
size and error if the buffer would be overwhelmed. That's usually an indication
that we should reject the data to begin with.

## Implement RFC 5780

My end goal is to provide a sans-IO library that implements the procedures
needed to perform operations as described in [RFC 5780][], such as determining
a NAT mapping or filtering, binding lifetime discovery, etc. This would include
both a client and server that could describe the needed operations, along with
a sans-IO implementation of the various operations.

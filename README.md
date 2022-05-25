This is a pet project of mine to implement the STUN protocol in pure Rust.

# Immediate TODO

* Implement the deserializing of individual attributes from iterator.
* Implement the deserializing of an error response.
* Implement the deserializing of binary into a binding request.
* Implement Fused iterator trait for attribute iterator.

* Implement the serializing of address into XOR-MAPPED blah blah)
* Implement the serializing of a binding request into binary. 

* Think about how to minimize use of dynamic memory for attributes.
* Build out server.

# Future TODOs

* Think a bit more about API.
* Validation of incoming request before attempting to read from it.
* Read up on additional items (nonces, fingerprints, etc.)
* Look for different ways to describe the binary decoding (nom, other libraries?)

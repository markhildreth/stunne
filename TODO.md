# TODO for stunne-protocol.

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


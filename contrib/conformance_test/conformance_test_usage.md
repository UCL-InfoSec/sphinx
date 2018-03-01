# Forward Sphinx message conformance test from X to Python

This is a conformance test that allows testing whether a forward message created using the given Sphinx client is conformant with the Python implementation of Sphinx. That is, if the given client were to be used to create a forward Sphinx message, and this message was forwarded to a Sphinx network that runs based off of the Python implementation, then it would be routed and received correctly.

## Usage of conformance test

Provided that `client_run_command` represents the command that runs the client under test (which works as specified below), the conformance test is ran as follows:
```
python3 conformance_test.py 'client_run_command'
```
For example, the provided `conformance_client.py` would be tested as follows:
```
python3 conformance_test.py 'python3 conformance_client.py'
```
The test will generate parameters for the client (as specified below), execute it and capture the standard output. It will then simulate routing the resulting message through a Sphinx network using the Python implementation, and checks if it gets routed correctly. `Success` will be printed if the test is successful, `Failure` otherwise.

## Specification for client under test

To perform the conformance test, the client under test must be implemented according to the specification described below. An example "conformance client" implemented in Python can be seen in the `conformance_client.py` file.

The client under test must be runnable from the command line, and accept command line arguments in the following format:
```
client_run_command [destination] [message] [mix_node_1_id]:[mix_node_1_public_key] [mix_node_2_id]:[mix_node_2_public_key] ...
```
For example, like this:
```
python3 conformance_client.py Ym9i dGhpcyBpcyBhIHRlc3Q= 4:AsNPySfFEjwKay1+w1PMeuURgZ9aLJjSbHdOaeo= 9:AntpLX/rveimvKCA1piwMTV4yKqH9b7EyXxROTw=
```
Specifics:
* `client_run_command` is a command that is used to run the client, that can contain spaces. For example:
  * `./client`
  * `python3 client.py`
  * `java -jar client.jar`
* `[destination]` is the Sphinx packet destination as a base64-encoded string
* `[message]` is the Sphinx packet message as a base64-encoded string
* `[mix_node_n_id]` is a string representation of the id for the n-th Sphinx node (e.g `1`)
* `[mix_node_n_public_key]` is a base64-encoded string representation of the n-th Sphinx node's public key
* The client should be able to accept a varying number of (id, public key) pairs

The client must use the input to create a forward Sphinx message, and pack it appropriately into a binary representation. It must then write this message to standard output.

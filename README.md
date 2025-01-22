# appguard-server

AppGuard is an **application-level firewall** for general applications.

Currently, AppGuard client libraries for Express and SMTP servers are available,
and support for more applications is planned for the future.

## Methodology

AppGuard consists of a **Rust-based gRPC server**
that receives and handles layer 7 network traffic from its clients.

The **server** is responsible for:
- logging layer 7 network traffic 
  - in console
  - in an SQLite database
- gathering additional IP information about each TCP connection (e.g., geolocation, ASN, organization, blacklist status), via
  - the [ipapi.co](https://ipapi.co) API
  - MaxMind databases from [ipinfo.io](https://ipinfo.io) updated daily
  - the [ipsum](https://github.com/stamparm/ipsum) daily updated feed of malicious IP addresses
- matching the traffic against a set of user-defined firewall rules that can be dynamically updated at runtime
- returning the result of the firewall rule matching to the client library

The **client libraries** are responsible for:
- sending the layer 7 network traffic to the gRPC server
- receiving the result of the firewall rule matching from the gRPC server, and acting accordingly

The contract between the server and the client libraries is defined in the [`appguard-protobuf/appguard.proto`](./appguard-protobuf/appguard.proto) file,
which adheres to the [Protocol Buffers](https://protobuf.dev/overview/) specification.

## Firewall specification

The firewall is defined in a JSON file, which is loaded by the server at startup and can be updated at runtime.

A firewall consists of a collection of **expressions**.<br>
Each expression is associated with a **policy** (either `allow` or `deny`) and a set of **tokens**.<br>
The expression's policy is applied if the tokens match the incoming traffic.

Firewall tokens are specified as a mathematical expression including **parenthesis**, **operators** (`AND`, `OR`), and **predicates**.<br>
Predicates include a matching **condition** (e.g., `equal`, `not_equal`, `lower_than`, `contains`, etc.) and a **value**.<br>
The value of a predicate explicitly refers to a field of the analyzed traffic
(e.g., the user agent, the source IP, a particular header, the response code, etc.).

For an example of a firewall specification, see the [`firewall.json`](./firewall.json) file.

Internally, each mathematical expression of the firewall is parsed
and converted to its equivalent [Reverse Polish Notation](https://en.m.wikipedia.org/wiki/Reverse_Polish_notation) (RPN),
also known as *postfix* form.<br>
The RPN form is then used to more efficiently evaluate the expression against the incoming traffic.

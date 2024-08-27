# java-sasl-did-mechanism

This repository is one component of the project "Securing Internet protocols with DIDs, using SASL",
see https://github.com/peacekeeper/did-based-sasl for an overview and list of all components.

## Description

The [Simple Authentication and Security Layer (SASL)](https://www.rfc-editor.org/rfc/rfc4422.html) is an extensible
framework for authentication in Internet protocols. It makes it possible to "plug in" authentication mechanisms into
existing protocols, by decoupling the authentication mechanisms from the application protocols.

Various SASL authentication mechanisms exist today, such as DIGEST-MD5, PLAIN, or GSSAPI. Known mechanisms are listed
in an IANA registry: https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml

This repository implements a new SASL authentication mechanism based on [Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/).
In this mechanism, a client is considered authenticated when it can successfully prove control of a DID. DIDs provide
built-in capabilities for proving such control, since DIDs can be resolved to a DID document, which contains technical
information about the identifier, including cryptographic keys. Therefore, control of a DID can be proven by using those
keys, e.g. to sign a challenge.

[DID Resolution](https://w3c.github.io/did-resolution/) is currently being standardized at the World Wide Web Consortium
(W3C). DID Resolution is implemented by resolvers, e.g. the [Universal Resolver](https://github.com/decentralized-identity/universal-resolver),
which is an open-source project maintained by the [Decentralized Identity Foundation (DIF)](https://identity.foundation/).
Other implementations of DID resolvers exist as well. In general, DIDs and the DID Resolution process are designed to
function without any dependency on central authorities or intermediaries.

This implementation of a DID-based SASL authentication mechanism uses the Java SASL API, which is provided by Java
Security in the package “javax.security.sasl”. More concretely, the DID-based SASL authentication mechanism is
implemented in the form of a security provider registered with the
[Java Cryptography Architecture (JCA)](https://docs.oracle.com/javase/9/security/java-cryptography-architecture-jca-reference-guide.htm).

The authentication process is based on a simple challenge/response flow, where the SASL server provides a challenge string,
and the SASL client signs the challenge using a DID's private key, and then transmits both the DID and the signature to
the SASL server. After the SASL server resolves the DID to obtain its public keys and verifies the signature, the SASL flow
concludes, and the host protocol (XMPP, LDAP, etc.) continues with the authenticated identifier.

In order to execute the flow and interact with the host protocol, the DID-based SASL authentication mechanism uses the following
callbacks:

- [NameCallBack](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/security/auth/callback/NameCallback.html) - To obtain the DID from the client
- [TextInputCallBack](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/security/auth/callback/TextInputCallback.html) - To obtain the DID's private key from the client, in order to create a signature

The name of the DID-based SASL authentication mechanism is "DID-CHALLENGE". Like other SASL authentication mechanisms, the
use of it can be negotiated between a server and a client.

## About

Markus Sabadello - https://github.com/peacekeeper/

<img align="left" height="40" src="https://github.com/peacekeeper/did-based-sasl/blob/main/docs/logo-ngi-assure.png?raw=true">

This project has received financial support from NLnet and the NGI Assure fund. NGI Assure was established with
financial support from the European Commission's Next Generation Internet programme, under the aegis of DG
Communications Networks, Content and Technology.
 
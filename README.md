# Modern Secure Channel on Certified Smartcards Using Ephemeral ECDH Keys

![GitHub tag (latest SemVer pre-release)](https://img.shields.io/github/v/tag/mvondracek/PV204_smartcards_Emerald?include_prereleases)
[![Build Status](https://travis-ci.org/mvondracek/PV204_smartcards_Emerald.svg?branch=master)](https://travis-ci.org/mvondracek/PV204_smartcards_Emerald)
[![Test Coverage](https://api.codeclimate.com/v1/badges/c9de1ba1e64b36d39113/test_coverage)](https://codeclimate.com/github/mvondracek/PV204_smartcards_Emerald/test_coverage)
[![Maintainability](https://api.codeclimate.com/v1/badges/c9de1ba1e64b36d39113/maintainability)](https://codeclimate.com/github/mvondracek/PV204_smartcards_Emerald/maintainability)

> [Security Technologies (PV204)](https://is.muni.cz/predmet/fi/jaro2020/PV204?lang=en)\
> [Faculty of Informatics (FI)](https://www.fi.muni.cz/index.html.en)\
> [Masaryk University (MU)](https://www.muni.cz/en)

**Team** Emerald:
[@OTristanF](https://github.com/OTristanF),
[@lsolodkova](https://github.com/lsolodkova),
[@mvondracek](https://github.com/mvondracek) (in alphabetical order).

The project aims to create a JavaCard applet and a PC application for secure channel
communication. The user is provided with a smart card (Java Card) with pre-personalized
4-digit PIN and a paper with this PIN printed. If the user wants to use the card, they have to put
it into the reader and type in the PIN.

Before any session, both card and a user (via implemented PC application) need to be mutually
authenticated, and all subsequent data exchange between them needs to be protected by a
secure channel. The PIN is never transmitted to the card or back. Therefore, they use it to
establish an initial secret for the secure channel using a key exchange over an elliptic curve,
which can then be used to derive session keys

|**Detailed report is available under [docs/](%2Fdocs%2FModern%20Secure%20Channel%20on%20Certified%20Smart%20Cards%20Using%20Ephemeral%20ECDH%20Keys%2C%20report%202020-04-23%2F) folder.**|
|---|

## Secure Channel Protocol Design

<img height="700em" src="%2Fdocs%2FModern%20Secure%20Channel%20on%20Certified%20Smart%20Cards%20Using%20Ephemeral%20ECDH%20Keys%2C%20report%202020-04-23%2Fimages%2Fimage1.png"/>

Our protocol implements *Password-Authenticated Key Exchange by Juggling* (J-PAKE) with
*Schnorr Non-Interactive Zero-Knowledge Proof* (ZKP) for key agreement and
the secure channel offers following security properties:

  - [x] Key agreement (J-PAKE)
  - [x] Authentication (ZKP)
  - [x] Protection against brute-force attacks (J-PAKE, ZKP)
  - [x] Perfect forward secrecy (new keys each session)
  - [x] Integrity (HMAC)
  - [x] Protection against replay attacks (hash chain)
  - [x] Confidentiality (AES-CBC)
  - [x] Random IVs for AES-CBC (cryptographically secure random number generator)
  - [x] Separate keys for AES-CBC and HMAC
  - [x] Protection against PIN brute-force attack (card applet blocking, PC application termination)
  - [x] Protection against memory dump attack (PC application discards PIN after use)
  - [x] Messages protected including their metadata

## Example Computer Application

*Emerald Password Manager for Smartcards* can communicate with the applet on
smartcard over secure channel. User needs to authenticate using PIN. The
application allows a user to save passwords to password manager inside the
card. Authenticated user can later retrieve saved passwords from the card.

~~~batch
.\gradlew.bat run -q --console=plain
~~~

~~~shell script
./gradlew run -q --console=plain
~~~

Examples of application output for [correct PIN](%2Fdocs%2Fcorrect%20PIN.txt)
and [incorrect PIN](%2Fdocs%2Fincorrect%20PIN.txt)
are avaialble in [docs/](%2Fdocs%2F)
folder.

## Testing

Our solution is tested with unit tests and end-to-end tests with APDUs. We have utilized
[Continuous Integration (Continuous Testing) via TravisCI](https://travis-ci.org/github/mvondracek/PV204_smartcards_Emerald/branches).
Code was also continuously checked with [SAST tools from Code Climate](https://codeclimate.com/github/mvondracek/PV204_smartcards_Emerald).
Tests can be executed locally as follows:

~~~batch
.\gradlew.bat check
~~~

~~~shell script
./gradlew check
~~~

## Requirements

[Java SE Development Kit 8](https://www.oracle.com/java/technologies/javase-jdk8-downloads.html)
is required to correctly build and run our solution. Dependencies are managed
by Gradle.

## Contributing

Our project is divided into three modules written in Java language as follows:

  - `applet`: Java Card applet managing communication over our secure channel and
    providing messages to Sub-Applet *Emerald Password Manager for Smart Cards*.
    The top-level applet serves as a secure layver for generic Sub-Applets.
  - `emApplication`: PC application for communication with *Emerald Password Manager
    for Smart Cards* on Java Card in smart card reader over our secure channel.
  - `emCardTools`: Tools for communication with smart card reader used in the PC
    application and during end-to-end testing of the applet. These tools are
    integrated from [crocs-muni/javacard-gradle-template-edu](https://github.com/crocs-muni/javacard-gradle-template-edu)
    which was published under MIT license.

We use [Gradle](https://gradle.org/) for build process, dependency management, testing, and also easy
execution. Gradle configuration for Java Card project was also based on [crocs-muni/javacard-gradle-template-edu](https://github.com/crocs-muni/javacard-gradle-template-edu), but was extended to better fit needs of our team.

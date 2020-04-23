# Modern Secure Channel on Certified Smartcards Using Ephemeral ECDH Keys

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

## Example computer application

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

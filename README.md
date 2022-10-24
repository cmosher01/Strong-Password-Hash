# Strong-Password-Hash

Copyright © 2018-2022, Christopher Alan Mosher, Shelton, Connecticut, USA, <cmosher01@gmail.com>.

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=CVSSQ2BWDCKQ2)
[![License](https://img.shields.io/github/license/cmosher01/Strong-Password-Hash.svg)](https://www.gnu.org/licenses/gpl.html)

PBKDF hashing command-line program, and Java library.

---

### usage

```groovy
repositories {
    mavenCentral()
    maven {
        url = uri('https://public:\u0067hp_fya6Kseu3XOBMg2icbg7f1LP6ZFYjj35v4Zj@maven.pkg.github.com/cmosher01/*')
    }
}

dependencies {
    implementation group: 'nu.mine.mosher.security.password', name: 'strong-password-hash', version: 'latest.release'
}
```

```java
import nu.mine.mosher.security.password.StrongHash;

    ...
    String password;
    ...
    String hash = StrongHash.hash(password); 
```

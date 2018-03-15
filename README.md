# Crypto JavaCard

This javacard can do the following actions:

- Load a Public/Private key on the card 
- Request the public key from the card
- Sign a precomputed hash using ECDSA on the card

This project is based on the [hardware wallet](https://github.com/status-im/hardware-wallet) implementation on the javacard. 

The project is built using Gradle with the [Fidesmo Javacard Gradle plugin](https://github.com/fidesmo/gradle-javacard).
You can set the JavaCard HOME not only through the environment but also creating a gradle.properties file with the 
property "com.fidesmo.gradle.javacard.home" set to the correct path.

Testing is done with JUnit and performed either on a real card or on [jCardSim](https://github.com/licel/jcardsim). You 
can specify to use the real card or simulator by changing the `com.crypterac.card.test.simulated` value in the `gradle.properties` 
file.

In order to test with the simulator with an IDE, you need to pass these additional parameters to the JVM

```-noverify -Dcom.crypterac.card.test.simulated=true```

## Dependencies
In the `lib/` folder, there are two dependencies:
1. The Javacard 3.0.4 library
2. Jcardsim project (forked version developed by [com-status](https://github.com/status-im/jcardsim) )
3. The GP jar used for installing on the card ([GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro))

## Compilation
1. Run `./gradlew convertJavacard`

## Testing
1. Make sure your JRE has the [JCE Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)
   installed. For more information check [here](https://stackoverflow.com/questions/41580489/how-to-install-unlimited-strength-jurisdiction-policy-files).
2. Run `./gradlew test`

## Installation
1. Follow all steps from the Compilation phase (except the last one). This will create the `.cap` file in `build/javacard/com/status/wallet/javacard`.
2. Disconnect all card reader terminals from the system, except the one with the card where you want to install the applet.
3. Run `./gradlew install`

## Implementation notes

* The applet requires JavaCard 3.0.4 or later.

The card support are at least:
* KeyPair.ALG_EC_FP (generation of 256-bit keys)
* Signature.ALG_ECDSA_SHA_256

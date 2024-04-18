# quickgcm
A simple wrapper for the WEB Crypto API, to rapidly use AES-GCM mode encryption with PBKDF2 for a password

# What
This is a very simple JavaScript module that works with Node and also in your browser.
It encrypts and decrypts strings based on a given password.

It uses PBKDF2 to derive the key based on the given password and it uses AES
with [Gallois/Counter Mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode) in order to encrypt data.
Considering that, every time the encryption method is ran, a different output will be
evaluated, even when ran for the same combination of string, password and salt.

The output of the encryption is a string in hexadecimal form, where the first 12 bytes
represent the [IV](https://en.wikipedia.org/wiki/Initialization_vector) and the following
bytes represent the encrypted data.

For example, given the following encrypted string:

`1cef377b00a44938327754b306b93e05ce54db6831c3135be140ccc6841a107367025bec516b405f3b`

- `1cef377b00a44938327754b3` represents the **IV**.
- `06b93e05ce54db6831c3135be140ccc6841a107367025bec516b405f3b` represents the **encrypted data**.

# Installation
This section describes how to install QuickGCM as a NodeJS package and how to use it in your browser as a
standalone script.

### For NPM
-

### For Browsers
To use in your browser, you can simply use the `quickgcm.js` file removing its last line,
that contains the export instruction, i.e. `module.exports = QuickGCM;`.
After doing that, just refer to the file by using a `script` tag or simply copying and
pasting it inside the browser's console.

# Usage
Below are some usage examples

### Encrypting and decrypting data
```javascript
const gcm = new QuickGCM();
const salt = await gcm.init('password123'); // outputs password salt as a hex string

const encrypted = await gcm.encrypt('Hello, World!'); // random hex string
const decrypted = await gcm.decrypt(encrypted); // "Hello, World!"
```

### Decrypting data previously encrypted
**Note that, if you want to save the encrypted strings to decrypt later,
it's also important to save the password salt, otherwise the decryption process won't work**

So, for that, assume the following values:
* **password**: `123456789`
* **password salt**: `9d10687df78f4f7cde49ddd51f675ca28b16f29c774acb33cacd638de8b2c5273948383bdf1727e81ee29c8e142840832e930a6184986fb66ca28e39d750acd31ed21ff4e14f80cb88f09627adc1f85ca35ee16cad5c9ef46d7f2359615b1e5de17538894f32d27db50b5ee71e3f0c0ce963b946de315d121e892e8a77e68d70`
* **encrypted string**: `5879fd94c5ff0e393f3446d34a4a30cddfe188242f95414f97ae27e8b5ef266a470eed523ecbe3d502b16d54fe04ed721f5721f78de15ef9f5`

Full code:

```javascript
const password = '123456789';
const salt = '9d10687df78f4f7cde49ddd51f675ca28b16f29c774acb33cacd638de8b2c5273948383bdf1727e81ee29c8e142840832e930a6184986fb66ca28e39d750acd31ed21ff4e14f80cb88f09627adc1f85ca35ee16cad5c9ef46d7f2359615b1e5de17538894f32d27db50b5ee71e3f0c0ce963b946de315d121e892e8a77e68d70';
const encrypted = '5879fd94c5ff0e393f3446d34a4a30cddfe188242f95414f97ae27e8b5ef266a470eed523ecbe3d502b16d54fe04ed721f5721f78de15ef9f5';

const gcm = new QuickGCM();
await gcm.init(password, salt);

assert(gcm.salt == salt); // both are the same

const decrypted = await gcm.decrypt(encrypted); // "Decrypted by another instance"
```

# Why
Every now and again I need, for no reason in particular, use some sort of simple string encryption,
so I have to look ou the [*WEB Crypto API*](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) documentation and build everything from scratch,
which it's pretty boring. So, I decided to make this simple encryption class in order
to have a quick and dirty way to encrypt and decrypt strings in JavaScript, regardless
if I'm working with NodeJS or writing some code for the browser.

## But, why AES-GCM in particular?
The choice of Gallois/Counter Mode was made based on the fact that it's a pretty fast
and modern encryption mode for AES, and it's used even by high stakes encryption protocols,
such as [TLS v1.2](https://www.ietf.org/rfc/rfc5288.txt)

# How about browser compatibility?
This module uses *private class methods* and *crypto subtle*, so any browser updated after 2022 should be compatible.
For more details on compatibility, such as precise dates that each browser started supporting these features,
check out the compatibility tables linked below, provided my MDN Web Docs.

- [WEB Crypto API - Compatibility](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API#browser_compatibility)
- [Classes compatibility (check 'private class methods')](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Classes#browser_compatibility)

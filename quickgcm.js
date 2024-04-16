class QuickGCM {
    #ALGORITHM = 'AES-GCM';
    #ALLOWED_KEY_LENGTHS = [128, 192, 256];
    #ALLOWED_KEY_USAGES = [
        'encrypt',
        'decrypt',
        'wrapKey',
        'unwrapKey',
    ];
    #ALLOWED_HASHES = [
        'SHA-1',
        'SHA-256',
        'SHA-384',
        'SHA-512',
    ];

    #enc = new TextEncoder();
    #dec = new TextDecoder();

    #keyLength;
    #keyUsages;
    #hash;
    #hashIterations;
    #saltLength;

    #key;
    #salt;

    #isAllowedKeyLength(length) {
        return this.#ALLOWED_KEY_LENGTHS.includes(length);
    }

    #isAllowedHash(hash) {
        return this.#ALLOWED_HASHES.includes(hash);
    }

    #checkKeyUsages(usages) {
        const unknown = usages.reduce((unknown, current) => {
            if (!this.#ALLOWED_KEY_USAGES.includes(current)) {
                unknown.push(current);
            }

            return unknown;
        }, []);

        return {
            error: unknown.length > 0,
            unknown,
        };
    }

    constructor(keyLength, keyUsages, hash, hashIterations, saltLength, password, salt) {
        if (!this.#isAllowedKeyLength(keyLength)) {
            throw Error(`Key length of "${keyLength}" is not allowed.`);
        }

        const keyUsageData = this.#checkKeyUsages(keyUsages);
        if (keyUsageData.error) {
            throw Error(`Key usages of "[${keyUsageData.unknown}]" are unknown or not allowed.`);
        }

        if (!this.#isAllowedHash(hash)) {
            throw Error(`Hash digest "${hash}" not allowed.`);
        }

        if (password == null) {
            throw Error('Password must not be null.');
        }

        this.#keyLength = keyLength;
        this.#keyUsages = keyUsages;
        this.#hash = hash;
        this.#hashIterations = hashIterations;
        this.#saltLength = saltLength;

        this.#key = this.#deriveKey(password, salt);
    }

    // Returns a new instance of QuickGCM with a 256 bits key that can be used to encrypt and decrypt data.
    static basicUsage(password, salt = crypto.getRandomValues(new Uint8Array(32))) {
        return new QuickGCM(256, ['encrypt', 'decrypt'], 'SHA-512', 1e5, 32, password, salt);
    }

    #encodeData(data) {
        return this.#enc.encode(data);
    }

    #decodeData(data) {
        return this.#dec.decode(data);
    }

    async #baseKey(password) {
        return crypto.subtle.importKey(
            'raw',
            this.#encodeData(password),
            'PBKDF2',
            false,
            ['deriveKey'],
        );
    }

    async #deriveKey(password, salt) {
        const baseKey = await this.#baseKey(password);
        const algorithm = {
            name: 'PBKDF2',
            hash: this.#hash,
            salt: salt,
            iterations: this.#hashIterations,
        };

        this.#key = await crypto.subtle.deriveKey(
            algorithm,
            baseKey, 
            { name: this.#ALGORITHM, length: this.#keyLength },
            true,
            this.#keyUsages,
        );

        return this.#key
    }

    #generateIV() {
        return crypto.getRandomValues(new Uint8Array(12));
    }
    
    async #getKey(format) {
        return crypto.subtle.exportKey(format, this.#key);
    }

    #hexToArrayBuffer(data) {
        assert(data.length % 2 == 0, 'Invalid hex length. It must be a power of 2');

        const bytePairs = data.match(/..?/g);

        return bytePairs.reduce((buf, value, i) => {
            buf[i] = parseInt(value, 16);
            return buf;
        }, new Uint8Array(bytePairs.length));
    }

    async rawKey() {
        return this.#getKey('raw');
    }

    async jwkKey() {
        return this.#getKey('jwk');
    }

    async #encrypt(data) {
        const iv = this.#generateIV();
        const encryptedData = await crypto.subtle.encrypt(
            { name: this.#ALGORITHM, iv: iv },
            this.#key,
            this.#encodeData(data),
        );

        return { encryptedData, iv };
    }

    async encryptRaw(data) {
        return this.#encrypt(data);
    }

    #typedArrayToHex(buffer) {
        const asArray = new Uint8Array(encrypted.encryptedData);

        return Array.from(asArray)
            .map(v => ('0' + v.toString(16)).slice(-2)).join('');
    }

    async encryptToHex(data) {
        const encrypted = await this.#encrypt(data);

        const hex = this.#typedArrayToHex(encrypted.encryptedData);

        return { hex, iv: encrypted.iv };
    }

    async #decrypt(data, iv, key = this.#key) {
        return crypto.subtle.decrypt(
            { name: this.#ALGORITHM, iv: iv },
            key,
            data,
        );
    }

    async decryptRaw(data, iv, key = this.#key) {
        return this.#decrypt(data, iv, key);
    }

    async decryptRawToString(data, iv, key = this.#key) {
        return this.#decrypt(data, iv, key)
            .then(raw => this.#decodeData(raw));
    }

    async decryptHexRaw(data, iv, key = this.#key) {
        const bufferData = this.#hexToArrayBuffer(data)

        return this.#decrypt(bufferData, iv, key);
    }

    async decryptHexToString(data, iv, key = this.#key) {
        const bufferData = this.#hexToArrayBuffer(data)

        return this.#decrypt(bufferData, iv, key)
            .then(raw => this.#decodeData(raw));
    }
}

module.exports = QuickGCM;

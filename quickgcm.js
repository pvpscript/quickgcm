class QuickGCM {
    #ALGORITHM = 'AES-GCM';
    #ALLOWED_KEY_LENGTHS = [128, 192, 256];
    #ALLOWED_KEY_USAGES = [
        'encrypt',
        'decrypt',
        'wrapKey',
        'unwrapKey',
    ];

    #enc = new TextEncoder();
    #dec = new TextDecoder();

    #keyLength;
    #keyUsages;
    #key;

    #isAllowedKeyLength(length) {
        return this.#ALLOWED_KEY_LENGTHS.includes(length);
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

    constructor(keyLength, keyUsages) {
        if (!this.#isAllowedKeyLength(keyLength)) {
            throw Error(`Key length of "${keyLength}" is not allowed.`);
        }

        const keyUsageData = this.#checkKeyUsages(keyUsages);
        if (keyUsageData.error) {
            throw Error(`Key usages of "[${keyUsageData.unknown}]" are unknown or not allowed.`);
        }

        this.#keyLength = keyLength;
        this.#keyUsages = keyUsages;
    }

    // Returns a new instance of QuickGCM with a 256 bits key that can be used to encrypt and decrypt data.
    static basicUsage() {
        return new QuickGCM(256, ['encrypt', 'decrypt']);
    }

    #encodeData(data) {
        return this.#enc.encode(data);
    }

    #decodeData(data) {
        return this.#dec.decode(data);
    }

    async #generateKey() {
        this.#key = await crypto.subtle.generateKey(
            { name: this.#ALGORITHM, length: this.#keyLength },
            true,
            this.#keyUsages,
        );

        return this.#key;
    }

    #generateIV() {
        return crypto.getRandomValues(new Uint8Array(12));
    }
    
    async #getKey(format) {
        if (typeof this.#key === 'undefined') {
            await this.#generateKey();
        }

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
        if (typeof this.#key === 'undefined') {
            await this.#generateKey();
        }

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

    async encryptToHex(data) {
        const encrypted = await this.#encrypt(data);

        const asArray = new Uint8Array(encrypted.encryptedData);

        const hex = Array.from(asArray)
            .map(v => ('0' + v.toString(16)).slice(-2)).join('');

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
            .then(raw => this.#dec.decode(raw));
    }

    async decryptHexRaw(data, iv, key = this.#key) {
        const bufferData = this.#hexToArrayBuffer(data)

        return this.#decrypt(bufferData, iv, key);
    }

    async decryptHexToString(data, iv, key = this.#key) {
        const bufferData = this.#hexToArrayBuffer(data)

        return this.#decrypt(bufferData, iv, key)
            .then(raw => this.#dec.decode(raw));
    }
}

module.exports = QuickGCM;

class QuickGCM {
    #ALGORITHM = 'AES-GCM';
    #IV_LENGTH = 12;

    #enc = new TextEncoder();
    #dec = new TextDecoder();

    #key;
    #salt;

    constructor() {}

    async init(password, salt) {
        this.#salt = salt || this.#generateSalt();
        this.#key = await this.#deriveKey(password, this.#salt);

        return this.#salt;
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
            hash: 'SHA-512',
            salt: this.#salt,
            iterations: 1e5,
        };

        return crypto.subtle.deriveKey(
            algorithm,
            baseKey, 
            { name: this.#ALGORITHM, length: 256 },
            true,
            ['encrypt', 'decrypt'],
        );
    }

    #generateSalt() {
        return crypto.getRandomValues(new Uint8Array(128));
    }

    #generateIV() {
        return crypto.getRandomValues(new Uint8Array(this.#IV_LENGTH));
    }

    #typedArrayToHex(buffer) {
        const asArray = new Uint8Array(buffer);

        return Array.from(asArray)
            .map(v => ('0' + v.toString(16)).slice(-2)).join('');
    }

    #hexToUint8Array(data) {
        assert(data.length % 2 == 0, 'Invalid hex length. It must be a power of 2');

        const bytePairs = data.match(/..?/g);

        return bytePairs.reduce((buf, value, i) => {
            buf[i] = parseInt(value, 16);
            return buf;
        }, new Uint8Array(bytePairs.length));
    }

    async #encrypt(data) {
        const iv = this.#generateIV();
        const encryptedData = await crypto.subtle.encrypt(
            { name: this.#ALGORITHM, iv: iv },
            this.#key,
            this.#encodeData(data),
        ).then(encrypted => new Uint8Array(encrypted));

        return { encryptedData, iv };
    }

    async encrypt(data) {
        const encrypted = await this.#encrypt(data);
        const bufLength = encrypted.encryptedData.length + encrypted.iv.length;

        const fullData = new Uint8Array(bufLength);

        fullData.set(encrypted.iv, 0);
        fullData.set(encrypted.encryptedData, encrypted.iv.length);

        return this.#typedArrayToHex(fullData);
    }

    async #decrypt(data, iv) {
        return crypto.subtle.decrypt(
            { name: this.#ALGORITHM, iv: iv },
            this.#key,
            data,
        );
    }

    async decrypt(data) {
        const rawData = this.#hexToUint8Array(data);

        const iv = rawData.slice(0, this.#IV_LENGTH);
        const encrypted = rawData.slice(this.#IV_LENGTH);

        const decrypted = await this.#decrypt(encrypted, iv);

        return this.#decrypt(encrypted, iv)
            .then(decrypted => this.#decodeData(decrypted));
    }

    get salt() {
        return this.#salt;
    }
}

module.exports = QuickGCM;

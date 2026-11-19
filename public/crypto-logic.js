// ============================================================================
// SYSTEM CORE: CRYPTOGRAPHIC LOGIC ENGINE (E2EE)
// ============================================================================

// =====================================
// GENERATE USER KEYS (RSA-OAEP)
// =====================================
async function generateUserKeys() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        true,
        ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']
    );
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
}

// =====================================
// EXPORT KEY TO JWK UTILITY
// =====================================
async function exportKeyToJwk(key) {
    return await window.crypto.subtle.exportKey('jwk', key);
}

// =====================================
// PBKDF2 KEY DERIVATION ENGINE
// Now uses a random per-user salt stored inside the encrypted key payload.
// Call deriveKeyFromPassword(password, saltBase64) at login time.
// Call deriveKeyFromPasswordWithNewSalt(password) at registration time.
// =====================================
async function deriveKeyFromPassword(password, saltBase64) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const saltBuffer = base64ToArrayBuffer(saltBase64);

    const baseKey = await window.crypto.subtle.importKey(
        'raw', passwordBuffer, { name: 'PBKDF2' }, false, ['deriveKey']
    );

    return await window.crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBuffer, iterations: 310000, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function deriveKeyFromPasswordWithNewSalt(password) {
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    const saltBase64 = arrayBufferToBase64(salt);
    const kek = await deriveKeyFromPassword(password, saltBase64);
    return { kek, saltBase64 };
}

// =====================================
// LOCAL PRIVATE KEY PROTECTION ENGINES
// Payload format: { ciphertext, iv, salt }
// salt is stored here so login can re-derive the KEK.
// =====================================
async function encryptPrivateKeyLocal(privateKeyJwkString, password) {
    const { kek, saltBase64 } = await deriveKeyFromPasswordWithNewSalt(password);
    const encoder = new TextEncoder();
    const rawData = encoder.encode(privateKeyJwkString);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const encryptedData = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv }, kek, rawData
    );

    return JSON.stringify({
        ciphertext: arrayBufferToBase64(encryptedData),
        iv: arrayBufferToBase64(iv),
        salt: saltBase64
    });
}

async function decryptPrivateKeyLocal(encryptedPayloadString, password) {
    try {
        const payload = JSON.parse(encryptedPayloadString.trim());

        if (!payload.salt) {
            throw new Error('Encrypted key payload is missing salt. Re-register this account.');
        }

        const kek = await deriveKeyFromPassword(password, payload.salt);
        const ciphertextBuffer = base64ToArrayBuffer(payload.ciphertext);
        const ivBuffer = base64ToArrayBuffer(payload.iv);

        const decryptedData = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: new Uint8Array(ivBuffer) }, kek, ciphertextBuffer
        );

        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    } catch (error) {
        console.error('Decryption failed:', error);
        throw new Error('Wrong password or corrupted key payload.');
    }
}

// =====================================
// ENCRYPT FILE (Hybrid Crypto)
// =====================================
async function encryptFile(file, publicKey) {
    const aesKey = await window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );

    const fileBuffer = await file.arrayBuffer();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const encryptedData = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv }, aesKey, fileBuffer
    );

    const wrappedKey = await window.crypto.subtle.wrapKey(
        'raw', aesKey, publicKey, { name: 'RSA-OAEP' }
    );

    return {
        blob: new Blob([encryptedData]),
        wrappedKey: arrayBufferToBase64(wrappedKey),
        iv: arrayBufferToBase64(iv)
    };
}

// =====================================
// DECRYPT FILE
// =====================================
async function decryptFile(encryptedBuffer, wrappedKeyBase64, ivBase64, privateKey) {
    const wrappedKey = base64ToArrayBuffer(wrappedKeyBase64);
    const ivBuffer = base64ToArrayBuffer(ivBase64);

    const aesKey = await window.crypto.subtle.unwrapKey(
        'raw', wrappedKey, privateKey,
        { name: 'RSA-OAEP' },
        { name: 'AES-GCM', length: 256 },
        true, ['decrypt']
    );

    return await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(ivBuffer) }, aesKey, encryptedBuffer
    );
}

// =====================================
// PROXY RE-ENCRYPTION FILE SHARING
// Re-wraps the file's real AES key for the recipient's public key.
// =====================================
async function prepareSharedKey(originalWrappedKeyBase64, myPrivateKey, recipientPublicKeyJwk) {
    const wrappedKeyBuffer = base64ToArrayBuffer(originalWrappedKeyBase64);

    const aesKey = await window.crypto.subtle.unwrapKey(
        'raw', wrappedKeyBuffer, myPrivateKey,
        { name: 'RSA-OAEP' },
        { name: 'AES-GCM', length: 256 },
        true, ['encrypt', 'decrypt']
    );

    const recipientPublicKey = await window.crypto.subtle.importKey(
        'jwk',
        typeof recipientPublicKeyJwk === 'string' ? JSON.parse(recipientPublicKeyJwk) : recipientPublicKeyJwk,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true, ['wrapKey', 'encrypt']
    );

    const newlyWrappedKeyBuffer = await window.crypto.subtle.wrapKey(
        'raw', aesKey, recipientPublicKey, { name: 'RSA-OAEP' }
    );

    return arrayBufferToBase64(newlyWrappedKeyBuffer);
}

// ============================================================================
// UTILITIES
// ============================================================================
function arrayBufferToBase64(bufferOrView) {
    let binary = '';
    const bytes = bufferOrView instanceof Uint8Array ? bufferOrView : new Uint8Array(bufferOrView);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
    return bytes.buffer;
}

// ============================================================================
// KEY VAULT — closure-scoped in-memory key management
// Private key is NEVER stored in sessionStorage in plaintext.
// On tab reload the user must log in again (password required to decrypt).
// ============================================================================
const KeyVault = (function () {
    let _privateKey = null;
    let _publicKey = null;

    async function unlock(password, encryptedPrivateKeyPayload, publicKeySource) {
        const payloadStr = typeof encryptedPrivateKeyPayload === 'string'
            ? encryptedPrivateKeyPayload
            : JSON.stringify(encryptedPrivateKeyPayload);

        const decryptedJwkString = await decryptPrivateKeyLocal(payloadStr, password);
        const privateJwk = JSON.parse(decryptedJwkString);

        const publicJwk = typeof publicKeySource === 'string'
            ? JSON.parse(publicKeySource)
            : publicKeySource;

        _privateKey = await window.crypto.subtle.importKey(
            'jwk', privateJwk,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false, ['unwrapKey', 'decrypt']
        );

        _publicKey = await window.crypto.subtle.importKey(
            'jwk', publicJwk,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false, ['wrapKey', 'encrypt']
        );

        return true;
    }

    function lock() {
        _privateKey = null;
        _publicKey = null;
    }

    function isUnlocked() {
        return !!(_privateKey && _publicKey);
    }

    async function encryptFileForUpload(file) {
        if (!_publicKey) throw new Error('Vault is locked. Please log in again before uploading.');
        return await encryptFile(file, _publicKey);
    }

    async function decryptDownloadedFile(encryptedBuffer, wrappedKeyBase64, ivBase64) {
        if (!_privateKey) throw new Error('Vault is locked. Please log in again to decrypt files.');
        return await decryptFile(encryptedBuffer, wrappedKeyBase64, ivBase64, _privateKey);
    }

    // Exposes the in-memory private key only to trusted internal callers (e.g. shareFile)
    function getPrivateKey() {
        if (!_privateKey) throw new Error('Vault is locked.');
        return _privateKey;
    }

    return { unlock, lock, isUnlocked, encryptFileForUpload, decryptDownloadedFile, getPrivateKey };
})();

window.KeyVault = KeyVault;
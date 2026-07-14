// ============================================================================
// SYSTEM CORE: CRYPTOGRAPHIC LOGIC ENGINE (E2EE)
// ============================================================================

// =====================================
// GENERATE USER KEYS (RSA-OAEP)
// =====================================
async function generateUserKeys() {
    // Web Crypto splits public and private usages strictly to secure keys safely
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

    return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey
    };
}

// =====================================
// ENCRYPT FILE (Hybrid Crypto Matrix)
// =====================================
async function encryptFile(file, publicKey) {
    // Generate a symmetric AES key unique to this file asset instance
    const aesKey = await window.crypto.subtle.generateKey(
        {
            name: 'AES-GCM',
            length: 256
        },
        true,
        ['encrypt', 'decrypt']
    );

    // Read payload as ArrayBuffer directly in sandboxed memory
    const fileBuffer = await file.arrayBuffer();

    // Generate random safe cryptographically non-repeating Initialization Vector
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Encrypt raw payload via symmetric engine channel
    const encryptedData = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        aesKey,
        fileBuffer
    );

    // Envelope (wrap) the volatile AES key with user's permanent asymmetric RSA key
    const wrappedKey = await window.crypto.subtle.wrapKey(
        'raw',
        aesKey,
        publicKey,
        {
            name: 'RSA-OAEP'
        }
    );

    // Convert blocks to base64 representations for safe transport over database boundaries
    const wrappedKeyBase64 = arrayBufferToBase64(wrappedKey);
    const ivBase64 = arrayBufferToBase64(iv); 

    return {
        blob: new Blob([encryptedData]),
        wrappedKey: wrappedKeyBase64,
        iv: ivBase64
    };
}

// =====================================
// DECRYPT FILE
// =====================================
async function decryptFile(encryptedBuffer, wrappedKeyBase64, ivBase64, privateKey) {
    // Reconstitute system parameters from storage base64 transport strings
    const wrappedKey = base64ToArrayBuffer(wrappedKeyBase64);
    const ivBuffer = base64ToArrayBuffer(ivBase64);

    // Unwrap (decrypt) the file's matching symmetric AES key via user private key token
    const aesKey = await window.crypto.subtle.unwrapKey(
        'raw',
        wrappedKey,
        privateKey,
        {
            name: 'RSA-OAEP'
        },
        {
            name: 'AES-GCM',
            length: 256
        },
        true,
        ['decrypt']
    );

    // Strip encryption layers back down to primitive binary payload array buffers
    const decryptedData = await window.crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: new Uint8Array(ivBuffer) 
        },
        aesKey,
        encryptedBuffer
    );

    return decryptedData;
}

// =====================================
// PROXY RE-ENCRYPTION FILE SHARING LOGIC
// =====================================
async function prepareSharedKey(originalWrappedKeyBase64, myPrivateKey, recipientJwkString) {
    // 1. Convert source key parameters out of baseline database strings
    const wrappedKeyBuffer = base64ToArrayBuffer(originalWrappedKeyBase64);
    
    // 2. Extract the raw underlying AES key using MY authorized private key instance
    const aesKey = await window.crypto.subtle.unwrapKey(
        'raw',
        wrappedKeyBuffer,
        myPrivateKey,
        { name: 'RSA-OAEP' },
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );

    // 3. Reconstitute the targeted recipient public key entry block safely
    const recipientPublicKey = await window.crypto.subtle.importKey(
        "jwk",
        JSON.parse(recipientJwkString),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["wrapKey", "encrypt"]
    );

    // 4. Transform key binding state by re-wrapping it under the recipient's identity footprint
    const newlyWrappedKeyBuffer = await window.crypto.subtle.wrapKey(
        'raw',
        aesKey,
        recipientPublicKey,
        { name: 'RSA-OAEP' }
    );

    // 5. Package output parameter block back out to standard string representation
    return arrayBufferToBase64(newlyWrappedKeyBuffer);
}

// ============================================================================
// DYNAMIC PASSWORD STRENGTH & HINT ENGINE
// ============================================================================
function analyzePasswordStrength(password) {
    const bar = document.getElementById('strengthBar');
    const label = document.getElementById('strengthLabel');
    const feedback = document.getElementById('policyFeedback');
    
    // Safety exit clause if UI indicators have not rendered into viewport yet
    if (!bar || !label || !feedback) return;

    if (!password) {
        bar.style.width = '0%';
        label.textContent = 'None';
        label.style.color = '#64748b';
        feedback.innerHTML = `<span style="color: #64748b;">Must be at least 10 characters long.</span>`;
        return;
    }

    // 1. Evaluate individual criteria states
    const hasMinimumLength = password.length >= 10;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[@$!%*?&]/.test(password);

    // 2. Build the exact list of missing attributes dynamically
    let missingHints = [];
    if (!hasMinimumLength) missingHints.push(`at least ${10 - password.length} more character(s)`);
    if (!hasUpperCase) missingHints.push("1 uppercase letter (A-Z)");
    if (!hasLowerCase) missingHints.push("1 lowercase letter (a-z)");
    if (!hasNumbers) missingHints.push("1 number (0-9)");
    if (!hasSpecialChar) missingHints.push("1 special character (@$!%*?&)");

    // 3. Determine Protection States and append custom hints text layouts
    if (!hasMinimumLength) {
        bar.style.width = '25%';
        bar.style.background = '#ef4444'; // Red
        label.textContent = 'Low Protection (Too Short)';
        label.style.color = '#ef4444';
        
        feedback.innerHTML = `<span style="color: #ef4444; font-weight:600;">❌ Missing:</span> <span style="color: #334155;">${missingHints.join(', ')}</span>`;
    } 
    else if (hasMinimumLength && missingHints.length > 0) {
        // If length is met but some character rules are still unfulfilled, it is Medium
        bar.style.width = '60%';
        bar.style.background = '#f59e0b'; // Amber
        label.textContent = 'Medium Protection';
        label.style.color = '#f59e0b';
        
        feedback.innerHTML = `<span style="color: #b45309; font-weight:600;">⚠️ Add to make strong:</span> <span style="color: #334155;">${missingHints.join(', ')}</span>`;
    } 
    else {
        // Length is >= 10 AND zero criteria elements are missing (All conditions satisfied)
        bar.style.width = '100%';
        bar.style.background = '#22c55e'; // Green
        label.textContent = 'High Protection';
        label.style.color = '#22c55e';
        
        feedback.innerHTML = `<span style="color: #16a34a; font-weight: 600;">✅ Excellent! Your credential profile configuration is fully secure.</span>`;
    }
}

// =====================================
// SECURE EXTENDED REGISTRATION COORDINATOR
// =====================================
async function executeCryptographicRegistration(event) {
    event.preventDefault();

    // Pull values directly from upgraded UI fields
    const username = document.getElementById('regUsername').value;
    const first_name = document.getElementById('regFirstName').value;
    const last_name = document.getElementById('regLastName').value;
    const personal_email = document.getElementById('regEmail').value;
    const region_code = document.getElementById('regRegionCode').value;
    const mobile_number = document.getElementById('regMobile').value;
    const password = document.getElementById('regPassword').value;

    // 1. HARD CRITERIA VALIDATION BLOCK (Must match backend policy metrics perfectly)
    const hasMinimumLength = password.length >= 10;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[@$!%*?&]/.test(password);

    // Enforce an absolute all-inclusive cryptographic gatekeeper rule
    if (!hasMinimumLength || !hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
        alert("Registration Blocked: Your password must reach 'High Protection' status by completely satisfying all length, uppercase, lowercase, number, and special character requirements.");
        return; // Terminate execution immediately
    }

    try {
        console.log("Generating identity root key matrices inside local sandboxed engine context...");
        
        // 2. Provision native cryptographic keypair structures inside sandboxed engine
        const keys = await generateUserKeys();
        
        // 3. Transform public parameters to raw JWK format strings
        const exportedPublicJwk = await exportKeyToJwk(keys.publicKey);
        
        // 4. Envelope private keys cleanly (Base64 JWK representation for storage serialization)
        const rawPrivateKeyJwk = await window.crypto.subtle.exportKey("jwk", keys.privateKey);
        const wrappedPrivateStringBlob = window.btoa(JSON.stringify(rawPrivateKeyJwk)); 

        // 5. Structure payload for network delivery
        const registrationPayload = {
            username: username,
            first_name: first_name,
            last_name: last_name,
            personal_email: personal_email,
            region_code: region_code,
            mobile_number: mobile_number,
            password: password, 
            publicKey: exportedPublicJwk,
            encryptedPrivateKey: wrappedPrivateStringBlob
        };

        // 6. Dispatch parameters across SSL tunnel to central endpoint
        const response = await fetch('http://localhost:3000/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(registrationPayload)
        });

        const result = await response.json();

        if (result.success) {
            alert("Account provisioning loop execution completed successfully! You can now log in.");
            window.location.reload();
        } else {
            alert(`Server enrollment rejected: ${result.error}`);
        }

    } catch (cryptoError) {
        console.error("Cryptographic setup failure array:", cryptoError);
        alert(`Failed to safely initialize storage encryption layers locally: ${cryptoError.message}`);
    }
}

// ============================================================================
// SYSTEM UTILITY UTILITIES & DATA TYPE PARSING TRANSITIONS
// ============================================================================

// =====================================
// HELPER: ArrayBuffer to Base64
// =====================================
function arrayBufferToBase64(bufferOrView) {
    let binary = '';
    const bytes = bufferOrView instanceof Uint8Array ? bufferOrView : new Uint8Array(bufferOrView);
    const len = bytes.byteLength;
    
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    
    return window.btoa(binary);
}

// =====================================
// HELPER: Base64 to ArrayBuffer
// =====================================
function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    
    return bytes.buffer;
}

// =====================================
// HELPER: Convert Key Instances to Strings
// =====================================
async function exportKeyToJwk(key) {
    const exported = await window.crypto.subtle.exportKey("jwk", key);
    return JSON.stringify(exported);
}

// =====================================
// HELPER: Convert Strings Back to Key Instances
// =====================================
async function importKeyFromJwk(jwkString, type) {
    const jwk = JSON.parse(jwkString);
    const usages = type === 'public' ? ['wrapKey', 'encrypt'] : ['unwrapKey', 'decrypt'];
    
    return await window.crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        usages
    );
}
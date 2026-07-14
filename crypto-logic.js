<!DOCTYPE html>
<html>

<head>

    <title>E2EE Secure Vault</title>

    <style>

        body {
            font-family: Arial;
            padding: 20px;
            background: #f4f4f4;
        }

        .container {
            max-width: 700px;
            margin: auto;
            background: white;
            padding: 20px;
            border-radius: 10px;
        }

        input, button {
            padding: 10px;
            margin: 5px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        th, td {
            border: 1px solid #ccc;
            padding: 10px;
        }

        th {
            background: #eee;
        }

        .hidden {
            display: none;
        }

        .delete-btn {
            background-color: #ff4444;
            color: white;
            border: none;
            cursor: pointer;
        }

        .delete-btn:hover {
            background-color: #cc0000;
        }

    </style>

</head>

<body>

<div class="container">

    <h2>🔐 Secure E2EE File Vault</h2>

    <!-- ========================= -->
    <!-- LOGIN / REGISTER -->
    <!-- ========================= -->

    <div id="authSection">

        <h3>Login or Register</h3>

        <input
            type="text"
            id="username"
            placeholder="Username"
        >

        <input
            type="password"
            id="password"
            placeholder="Password"
        >

        <br>

        <button onclick="handleRegister()">
            Register
        </button>

        <button onclick="handleLogin()">
            Login
        </button>

    </div>


    <!-- ========================= -->
    <!-- VAULT -->
    <!-- ========================= -->

    <div id="vaultSection" class="hidden">

        <h3>
            Welcome,
            <span id="displayUser"></span>
        </h3>

        <button onclick="logout()">
            Logout
        </button>

        <hr>

        <input
            type="file"
            id="filePicker"
        >

        <button onclick="removeSelectedFile()">
            Remove Selected File
        </button>

        <button onclick="handleUpload()">
            Upload Encrypted File
        </button>

        <hr>

        <h3>Your Files</h3>

        <table>

            <thead>

                <tr>
                    <th>File Name</th>
                    <th>Actions</th>
                </tr>

            </thead>

            <tbody id="fileList"></tbody>

        </table>

    </div>

</div>


<script src="crypto-logic.js"></script>

<script>

let userKeys;
let loggedInUser = null;


// =====================================
// ON PAGE LOAD
// =====================================

window.onload = async () => {

    try {
        userKeys = await generateUserKeys();
        console.log('User keys generated successfully');
    } catch (error) {
        console.error('Error generating keys:', error);
        alert('Error initializing encryption keys. Please refresh the page.');
        return;
    }

    const savedUser = localStorage.getItem('loggedInUser');

    if (savedUser) {

        loggedInUser = JSON.parse(savedUser);

        document.getElementById('authSection').style.display = 'none';
        document.getElementById('vaultSection').style.display = 'block';
        document.getElementById('displayUser').innerText = loggedInUser.username;

        refreshFiles();
    }
};


// =====================================
// REGISTER
// =====================================

async function handleRegister() {

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    if (!username || !password) {
        alert('Username and password required');
        return;
    }

    try {
        const res = await fetch('http://localhost:3000/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const data = await res.json();

        if (data.success) {
            alert('Registration successful. Please login.');
        } else {
            alert(data.error || 'Registration failed');
        }
    } catch (error) {
        console.error('Registration error:', error);
        alert('Registration failed. Please check if server is running.');
    }
}


// =====================================
// LOGIN
// =====================================

async function handleLogin() {

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const res = await fetch('http://localhost:3000/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const data = await res.json();

        if (!data.success) {
            alert('Login failed');
            return;
        }

        // SAVE TOKEN
        localStorage.setItem('token', data.token);

        // SAVE USER
        localStorage.setItem('loggedInUser', JSON.stringify(data.user));

        loggedInUser = data.user;

        document.getElementById('authSection').style.display = 'none';
        document.getElementById('vaultSection').style.display = 'block';
        document.getElementById('displayUser').innerText = loggedInUser.username;

        refreshFiles();
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed. Please check if server is running.');
    }
}


// =====================================
// LOGOUT
// =====================================

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('loggedInUser');
    location.reload();
}


// =====================================
// UPLOAD FILE
// =====================================

async function handleUpload() {

    if (!loggedInUser) {
        alert('Please login');
        return;
    }

    const file = document.getElementById('filePicker').files[0];

    if (!file) {
        alert('Select a file');
        return;
    }

    try {
        console.log('Starting encryption...');

        // Check if encryptFile function exists
        if (typeof encryptFile !== 'function') {
            throw new Error('encryptFile function not found. Make sure crypto-logic.js is loaded.');
        }

        // Check if userKeys exists
        if (!userKeys || !userKeys.publicKey) {
            throw new Error('Encryption keys not initialized. Please refresh the page.');
        }

        const { blob, wrappedKey, iv } = await encryptFile(file, userKeys.publicKey);

        console.log('File encrypted successfully');

        const formData = new FormData();
        formData.append('file', blob);
        formData.append('fileName', file.name);
        formData.append('wrappedKey', wrappedKey);
        formData.append('iv', iv);

        const token = localStorage.getItem('token');

        console.log('Uploading to server...');

        const res = await fetch('http://localhost:3000/api/upload', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`
            },
            body: formData
        });

        const data = await res.json();

        if (data.success) {
            alert('Upload successful');
            document.getElementById('filePicker').value = '';
            refreshFiles();
        } else {
            alert('Upload failed: ' + (data.error || 'Unknown error'));
        }

    } catch (error) {
        console.error('Upload error:', error);
        alert('Upload failed: ' + error.message);
    }
}


// =====================================
// REMOVE SELECTED FILE FROM INPUT
// =====================================

function removeSelectedFile() {
    const filePicker = document.getElementById('filePicker');
    
    if (!filePicker.files.length) {
        alert('No file selected to remove');
        return;
    }
    
    filePicker.value = '';
    alert('Selected file removed from input');
}


// =====================================
// DELETE UPLOADED FILE FROM SERVER
// =====================================

async function deleteFile(fileId, fileName) {
    
    if (!confirm(`Are you sure you want to delete "${fileName}"?`)) {
        return;
    }

    try {
        const token = localStorage.getItem('token');

        const res = await fetch(`http://localhost:3000/api/delete/${fileId}`, {
            method: 'DELETE',
            headers: {
                Authorization: `Bearer ${token}`
            }
        });

        const data = await res.json();

        if (data.success) {
            alert('File deleted successfully');
            refreshFiles();
        } else {
            alert('Failed to delete file');
        }
    } catch (error) {
        console.error('Delete error:', error);
        alert('Failed to delete file: ' + error.message);
    }
}


// =====================================
// LOAD USER FILES
// =====================================

async function refreshFiles() {

    try {
        const token = localStorage.getItem('token');

        const res = await fetch('http://localhost:3000/api/files', {
            headers: {
                Authorization: `Bearer ${token}`
            }
        });

        const files = await res.json();

        const list = document.getElementById('fileList');

        list.innerHTML = files.map(f => `
            <tr>
                <td>${f.file_name}</td>
                <td>
                    <button onclick="downloadAndDecrypt(${f.id}, '${f.wrapped_key}', '${f.iv}', '${f.file_name}')">
                        Download & Decrypt
                    </button>
                    <button class="delete-btn" onclick="deleteFile(${f.id}, '${f.file_name}')">
                        Delete
                    </button>
                </td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('Refresh files error:', error);
    }
}


// =====================================
// DOWNLOAD & DECRYPT
// =====================================

async function downloadAndDecrypt(id, wrappedKey, iv, fileName) {

    try {
        const token = localStorage.getItem('token');

        const res = await fetch(`http://localhost:3000/api/download/${id}`, {
            headers: {
                Authorization: `Bearer ${token}`
            }
        });

        // GET ENCRYPTED FILE
        const encryptedBuf = await res.arrayBuffer();

        console.log('Decrypting file...');

        // DECRYPT FILE
        const decryptedBuf = await decryptFile(
            encryptedBuf,
            wrappedKey,
            iv,
            userKeys.privateKey
        );

        console.log('File decrypted successfully');

        // CREATE FILE URL
        const blob = new Blob([decryptedBuf]);
        const url = URL.createObjectURL(blob);

        // DOWNLOAD FILE
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

    } catch (error) {
        console.error('Download/decrypt error:', error);
        alert('Failed to download and decrypt file: ' + error.message);
    }
}

</script>

</body>
</html>
/* Hash */

const {createHash, generateKeyPairSync} = require("crypto");

function hash(input) {
    return createHash('sha256').update(input).digest('hex');
}

let password = "testingthisshit"
const hash1 = hash(password);
console.log(hash1);

/* Salt */

const {scryptSync, randomBytes, timingSafeEqual} = require("crypto");

let users = []

function signup(email, password) {
    const salt = randomBytes(16).toString('hex');
    const hashedPassword = scryptSync(password, salt, 64);

    const user = {email, password: `${salt}:${hashedPassword}`}

    users.push(user);

    return user
}

function login(email, password) {
    const user = users.find(u => u.email == email);

    const [salt, key] = user.password.split(":");
    const hashedBuffer = scryptSync(password, salt, 64)

    const keyBuffer = Buffer.from(key, 'key')
    const match = timingSafeEqual(hashedBuffer, keyBuffer)

    if (match) {
        return 'login success!'
    } else {
        return 'login fail'
    }
}

/* Hash-based message authentication */

const {createHmac} = require('crypto');

const key = 'super-secret!';
const lmessage = 'booo'
const spee = key.update(lmessage).digest('hex')

const hmac = createHmac('sha256', spee)

/* Symmetric encryption */

const {createCipheriv, createDecipheriv} = require("crypto");

const sMessage = "i love pandas";
const sKey = randomBytes(32);
const iv = randomBytes(16);

const cipher = createCipheriv('aes256', sKey, iv);

const encryptedSMessage = cipher.update(sMessage, 'utf-8', 'hex') + cipher.final('hex');

const decipher = createDecipheriv('aes256', sKey, iv);

const decryptedSMessage = decipher.update(encryptedSMessage, 'hex', 'utf-8') + decipher.final('utf-8');

console.log(decryptedSMessage);

/* Keypairs */

const {generateKeyPairSync} = require('crypto');

const {privateKey, publicKey} = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: 'top secret'
    }
})

/* Assymetric Encyription */

const {publicEncrypt, privateDecrypt} = require('crypto');

const crypt = "the guza is attacking the butt";

const encryptedData  = publicEncrypt(
    publicKey,
    Buffer.from(crypt)
)

const decryptedData = privateDecrypt(
    privateKey,
    encryptedData
)

/* Digital signature / signin */

const {createSign, createVerify} = require('crypto');

const bloop = "This message will die"

const signer = createSign('rsa-sha256');

signer.update(bloop);

const signature = signer.sign(privateKey);

const verifier = createVerify('rsa-sha256');

verifier.update(bloop);

const isVerfied = verifier.verify(publicKey, signature, 'hex');
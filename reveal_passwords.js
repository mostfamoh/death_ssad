// reveal_passwords.js
// Utility script for this educational project: attempt to recover stored passwords
// - For users in mode 'weak' it will decrypt using the stored cipher and params
// - For users in mode 'secure' it will indicate that the password cannot be recovered from pbkdf2 hash

const fs = require('fs');
const path = require('path');
const ciphers = require('./backend/utils/ciphers');

const DATA_DIR = path.join(__dirname, 'backend', 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

function loadUsers() {
  const raw = fs.readFileSync(USERS_FILE, 'utf8');
  return JSON.parse(raw).users || [];
}

function tryReveal(user) {
  if (user.mode === 'weak') {
    const cipher = user.cipher;
    const params = user.params || {};
    const stored = user.storedPassword;

    try {
      let recovered = null;
      switch (cipher) {
        case 'caesar':
          // Try all 26 shifts and pick one that yields readable text (best-effort)
          for (let s = 0; s < 26; s++) {
            const plain = ciphers.caesarDecrypt(stored, s);
            // crude check: plain contains vowels or lowercase letters
            if (/[aeiouyAEIOUY]/.test(plain)) { recovered = plain; break; }
          }
          if (!recovered) recovered = ciphers.caesarDecrypt(stored, params.shift || 3);
          return { success: true, method: 'caesar', recovered };

        case 'affine':
          // Brute-force affine
          const candidates = [];
          const validA = [1,3,5,7,9,11,15,17,19,21,23,25];
          for (const a of validA) {
            for (let b = 0; b < 26; b++) {
              try {
                const plain = ciphers.affineDecrypt(stored, a, b);
                if (/[aeiouyAEIOUY]/.test(plain)) {
                  return { success: true, method: 'affine', recovered: plain, params: {a,b} };
                }
              } catch(e){}
            }
          }
          return { success: false, reason: 'no readable candidate found' };

        case 'playfair':
          try {
            const key = params.key || 'SECRET';
            const plain = ciphers.playfairDecrypt(stored, key);
            return { success: true, method: 'playfair', recovered: plain };
          } catch (e) {
            return { success: false, reason: 'playfair decryption failed: ' + e.message };
          }

        case 'hill':
          try {
            const keyMatrix = params.keyMatrix || [[6,24,1],[13,16,10],[20,17,15]];
            const plain = ciphers.hillDecrypt(stored, keyMatrix);
            return { success: true, method: 'hill', recovered: plain };
          } catch (e) {
            return { success: false, reason: 'hill decryption failed: ' + e.message };
          }

        default:
          return { success: false, reason: 'unknown cipher' };
      }
    } catch (err) {
      return { success: false, reason: err.message };
    }
  } else if (user.mode === 'secure') {
    return { success: false, reason: 'secure mode (pbkdf2) - cannot recover plaintext from hash. Use verification or brute-force.' };
  } else {
    return { success: false, reason: 'unknown mode' };
  }
}

function main() {
  const users = loadUsers();
  if (!users.length) {
    console.log('No users found.');
    return;
  }

  console.log('\nAttempting to reveal stored passwords (educational only)\n');

  for (const u of users) {
    const result = tryReveal(u);
    console.log('---');
    console.log('username:', u.username);
    console.log('mode:', u.mode);
    if (u.mode === 'weak') console.log('cipher:', u.cipher, 'params:', JSON.stringify(u.params || {}));
    if (result.success) {
      console.log('Recovered plaintext:', result.recovered);
      if (result.params) console.log('Used params:', JSON.stringify(result.params));
    } else {
      console.log('Could not recover:', result.reason);
    }
  }
  console.log('\nDone.');
}

main();

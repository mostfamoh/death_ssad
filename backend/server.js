/**
 * TP Cryptographie Classique - Serveur Node.js (sans framework)
 * Module: http, fs, crypto uniquement
 * Endpoints: /register, /login, /dh, /simulate/mitm, /results.csv
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

// Import des modules utilitaires
const ciphers = require('./utils/ciphers');
const attacks = require('./utils/attacks');
const secure = require('./utils/secure');

const PORT = 3000;
const FRONTEND_DIR = path.join(__dirname, '..', 'frontend');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const RESULTS_FILE = path.join(DATA_DIR, 'results.csv');

// Initialisation des fichiers de données
function initDataFiles() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }, null, 2));
  }
  if (!fs.existsSync(RESULTS_FILE)) {
    fs.writeFileSync(RESULTS_FILE, 'timestamp,username,attack_type,target,attempts,elapsed_seconds,success,recovered_plaintext\n');
  }
}

// Chargement / sauvegarde utilisateurs
function loadUsers() {
  try {
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return { users: [] };
  }
}

function saveUsers(data) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
}

// Logger les résultats d'attaque
function logAttackResult(username, attackType, target, attempts, elapsed, success, recovered) {
  const timestamp = new Date().toISOString();
  const line = `${timestamp},${username},${attackType},${target},${attempts},${elapsed.toFixed(3)},${success},${recovered}\n`;
  fs.appendFileSync(RESULTS_FILE, line);
}

// Parser le body JSON
function parseBody(req, callback) {
  let body = '';
  req.on('data', chunk => body += chunk.toString());
  req.on('end', () => {
    try {
      callback(null, JSON.parse(body));
    } catch (e) {
      callback(e);
    }
  });
}

// Servir fichiers statiques
function serveStatic(res, filePath) {
  const ext = path.extname(filePath);
  const contentTypes = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml'
  };
  const contentType = contentTypes[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/html' });
        res.end('<h1>404 - File Not Found</h1>');
      } else {
        res.writeHead(500);
        res.end('Server Error');
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
}

// Handler pour /register
function handleRegister(req, res) {
  parseBody(req, (err, body) => {
    if (err || !body.username || !body.password || !body.mode) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid request' }));
      return;
    }

    const { username, password, mode, cipher, params } = body;
    const db = loadUsers();

    // Vérifier si l'utilisateur existe déjà
    if (db.users.find(u => u.username === username)) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'User already exists' }));
      return;
    }

    let stored = '';
    let note = '';

    if (mode === 'weak') {
      // Stockage faible: mot de passe chiffré par algorithme classique
      switch (cipher) {
        case 'caesar':
          const shift = params.shift || 3;
          stored = ciphers.caesarEncrypt(password, shift);
          note = `Stored with Caesar (shift ${shift})`;
          break;
        case 'affine':
          const { a, b } = params;
          stored = ciphers.affineEncrypt(password, a || 5, b || 8);
          note = `Stored with Affine (a=${a}, b=${b})`;
          break;
        case 'playfair':
          stored = ciphers.playfairEncrypt(password, params.key || 'SECRET');
          note = `Stored with Playfair (key: ${params.key})`;
          break;
        case 'hill':
          stored = ciphers.hillEncrypt(password, params.keyMatrix || [[6,24,1],[13,16,10],[20,17,15]]);
          note = `Stored with Hill 3x3`;
          break;
        default:
          stored = password;
          note = 'Stored in plaintext (very weak!)';
      }

      db.users.push({
        username,
        mode: 'weak',
        cipher,
        params,
        storedPassword: stored
      });
    } else if (mode === 'secure') {
      // Stockage sécurisé: pbkdf2 + salt
      const hashRecord = secure.hashPassword(password);
      db.users.push({
        username,
        mode: 'secure',
        salt: hashRecord.salt,
        derived: hashRecord.derived,
        iterations: hashRecord.iterations,
        keylen: hashRecord.keylen,
        digest: hashRecord.digest
      });
      note = 'Stored securely with pbkdf2 + salt';
    }

    saveUsers(db);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      stored: mode === 'weak' ? stored : '[hashed]',
      note
    }));
  });
}

// Handler pour /login
function handleLogin(req, res) {
  parseBody(req, (err, body) => {
    if (err || !body.username || !body.payload) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid request' }));
      return;
    }

    const { username, payload, payloadType, cipher, params, sessionKey } = body;
    const db = loadUsers();
    const user = db.users.find(u => u.username === username);

    if (!user) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'User not found' }));
      return;
    }

    let success = false;

    if (user.mode === 'weak') {
      // Mode faible: comparer ciphertext ou plaintext
      if (payloadType === 'ciphertext') {
        success = (payload === user.storedPassword);
      } else if (payloadType === 'plaintext') {
        // Chiffrer le plaintext et comparer
        let encrypted = '';
        switch (cipher) {
          case 'caesar':
            encrypted = ciphers.caesarEncrypt(payload, params.shift || 3);
            break;
          case 'affine':
            encrypted = ciphers.affineEncrypt(payload, params.a || 5, params.b || 8);
            break;
          case 'playfair':
            encrypted = ciphers.playfairEncrypt(payload, params.key || 'SECRET');
            break;
          case 'hill':
            encrypted = ciphers.hillEncrypt(payload, params.keyMatrix || [[6,24,1],[13,16,10],[20,17,15]]);
            break;
          default:
            encrypted = payload;
        }
        success = (encrypted === user.storedPassword);
      }
    } else if (user.mode === 'secure') {
      if (payloadType === 'hmac' && sessionKey) {
        // Vérifier HMAC basé sur session key
        const expectedHmac = secure.computeHMAC(sessionKey, payload);
        // Ici payload devrait être le HMAC, on vérifie le password
        // En réalité: client envoie HMAC(sessionKey, password)
        // On reconstruit HMAC(sessionKey, stored_password) - mais on a hash!
        // Pour simplicité pédagogique: on vérifie pbkdf2
        success = secure.verifyPassword(payload, user);
      } else {
        // Connexion directe avec password plaintext
        success = secure.verifyPassword(payload, user);
      }
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      success,
      message: success ? 'Authentication successful' : 'Authentication failed'
    }));
  });
}

// Handler pour /dh (échange Diffie-Hellman)
function handleDH(req, res) {
  parseBody(req, (err, body) => {
    if (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid request' }));
      return;
    }

    const { clientPublic, p, g } = body;

    // Paramètres DH (simplifiés pour démo)
    const prime = p || secure.DH_PARAMS.p;
    const generator = g || secure.DH_PARAMS.g;

    // Serveur génère sa paire
    const serverPrivate = secure.generateDHPrivate();
    const serverPublic = secure.computeDHPublic(generator, serverPrivate, prime);

    // Calcul de la clé partagée
    const sharedKey = secure.computeDHShared(clientPublic, serverPrivate, prime);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      serverPublic: serverPublic.toString(),
      sharedKey: sharedKey.toString(), // En prod, ne jamais renvoyer!
      note: 'Shared key computed (for educational purposes only - never send in production!)'
    }));
  });
}

// Handler pour /simulate/mitm
function handleSimulateMitm(req, res) {
  parseBody(req, (err, body) => {
    if (err || !body.username || !body.intercepted) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid request' }));
      return;
    }

    const { username, intercepted, cipher, params } = body;
    const db = loadUsers();
    const user = db.users.find(u => u.username === username);

    if (!user) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'User not found' }));
      return;
    }

    const results = {
      username,
      intercepted,
      attacks: []
    };

    // Brute-force selon le cipher
    if (cipher === 'caesar') {
      const startTime = Date.now();
      const candidates = attacks.bruteForceCaesar(intercepted);
      const elapsed = (Date.now() - startTime) / 1000;

      // Vérifier contre dictionnaire
      const dictPath = path.join(DATA_DIR, 'dict_small.txt');
      let dictMatches = [];
      if (fs.existsSync(dictPath)) {
        dictMatches = attacks.dictionaryAttack(candidates, dictPath);
      }

      const success = candidates.some(c => c.text.toLowerCase() === user.storedPassword?.toLowerCase());
      const recovered = success ? candidates.find(c => c.text.toLowerCase() === user.storedPassword?.toLowerCase()).text : '';

      logAttackResult(username, 'Caesar Brute-Force', intercepted, 26, elapsed, success, recovered);

      results.attacks.push({
        type: 'Caesar Brute-Force',
        attempts: 26,
        elapsed: elapsed.toFixed(3),
        candidates: candidates.slice(0, 10),
        dictMatches,
        success,
        recovered
      });
    }

    if (cipher === 'affine') {
      const startTime = Date.now();
      const candidates = attacks.bruteForceAffine(intercepted);
      const elapsed = (Date.now() - startTime) / 1000;

      const success = candidates.some(c => c.text === user.storedPassword);
      const recovered = success ? candidates.find(c => c.text === user.storedPassword).text : '';

      logAttackResult(username, 'Affine Brute-Force', intercepted, candidates.length, elapsed, success, recovered);

      results.attacks.push({
        type: 'Affine Brute-Force',
        attempts: candidates.length,
        elapsed: elapsed.toFixed(3),
        candidates: candidates.slice(0, 10),
        success,
        recovered
      });
    }

    // Dictionary attack direct
    const dictPath = path.join(DATA_DIR, 'dict_small.txt');
    if (fs.existsSync(dictPath)) {
      const startTime = Date.now();
      const words = fs.readFileSync(dictPath, 'utf8').split('\n').map(w => w.trim()).filter(Boolean);
      const matches = attacks.dictionaryDirectAttack(intercepted, words, user.cipher, user.params);
      const elapsed = (Date.now() - startTime) / 1000;

      const success = matches.length > 0;
      const recovered = success ? matches[0] : '';

      logAttackResult(username, 'Dictionary Attack', intercepted, words.length, elapsed, success, recovered);

      results.attacks.push({
        type: 'Dictionary Attack',
        attempts: words.length,
        elapsed: elapsed.toFixed(3),
        matches,
        success,
        recovered
      });
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(results));
  });
}

// Handler pour GET /results.csv
function handleResultsDownload(req, res) {
  if (fs.existsSync(RESULTS_FILE)) {
    res.writeHead(200, {
      'Content-Type': 'text/csv',
      'Content-Disposition': 'attachment; filename="results.csv"'
    });
    const stream = fs.createReadStream(RESULTS_FILE);
    stream.pipe(res);
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Results file not found');
  }
}

// Serveur principal
const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // CORS headers pour développement
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Routes API
  if (pathname === '/register' && req.method === 'POST') {
    handleRegister(req, res);
  } else if (pathname === '/login' && req.method === 'POST') {
    handleLogin(req, res);
  } else if (pathname === '/dh' && req.method === 'POST') {
    handleDH(req, res);
  } else if (pathname === '/simulate/mitm' && req.method === 'POST') {
    handleSimulateMitm(req, res);
  } else if (pathname === '/results.csv' && req.method === 'GET') {
    handleResultsDownload(req, res);
  } else if (pathname.startsWith('/user/') && req.method === 'GET') {
    // Récupérer les infos d'un utilisateur (sans le mot de passe)
    const username = pathname.split('/')[2];
    const db = loadUsers();
    const user = db.users.find(u => u.username === username);
    
    if (user) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: true,
        username: user.username,
        mode: user.mode,
        cipher: user.cipher,
        params: user.params
      }));
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'User not found' }));
    }
  } else if (pathname === '/' || pathname === '/index.html') {
    serveStatic(res, path.join(FRONTEND_DIR, 'index.html'));
  } else {
    // Servir fichiers statiques du frontend
    const filePath = path.join(FRONTEND_DIR, pathname);
    serveStatic(res, filePath);
  }
});

// Initialisation et démarrage
initDataFiles();
server.listen(PORT, () => {
  console.log(`\n╔════════════════════════════════════════════════════════════╗`);
  console.log(`║  TP Cryptographie Classique - Serveur démarré             ║`);
  console.log(`╠════════════════════════════════════════════════════════════╣`);
  console.log(`║  🌐 URL: http://localhost:${PORT}                           ║`);
  console.log(`║  📁 Frontend: ${FRONTEND_DIR.padEnd(38)} ║`);
  console.log(`║  💾 Data: ${DATA_DIR.padEnd(42)} ║`);
  console.log(`╚════════════════════════════════════════════════════════════╝\n`);
});

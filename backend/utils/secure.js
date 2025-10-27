/**
 * secure.js - Fonctions de sécurité (Diffie-Hellman, pbkdf2, HMAC)
 * Démonstration pédagogique d'échange de clés et stockage sécurisé
 */

const crypto = require('crypto');

// ============================================================================
// PARAMÈTRES DIFFIE-HELLMAN (simplifiés pour démo)
// ============================================================================

/**
 * Paramètres DH publics (groupe modp14 simplifié)
 * En production: utiliser des groupes standards (RFC 3526) ou ECDH
 */
const DH_PARAMS = {
  // Prime modulus (petit pour démo, utiliser 2048+ bits en prod)
  p: BigInt('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'),
  
  // Générateur
  g: BigInt(2)
};

// ============================================================================
// DIFFIE-HELLMAN: GÉNÉRATION ET ÉCHANGE
// ============================================================================

/**
 * Génère un exposant privé aléatoire pour DH
 * En prod: utiliser au moins 256 bits d'entropie
 */
function generateDHPrivate(bits = 128) {
  const bytes = Math.ceil(bits / 8);
  const randomBytes = crypto.randomBytes(bytes);
  return BigInt('0x' + randomBytes.toString('hex'));
}

/**
 * Calcule la clé publique: public = g^private mod p
 */
function computeDHPublic(g, privateKey, p) {
  return modPow(BigInt(g), BigInt(privateKey), BigInt(p));
}

/**
 * Calcule la clé partagée: shared = otherPublic^private mod p
 */
function computeDHShared(otherPublic, privateKey, p) {
  return modPow(BigInt(otherPublic), BigInt(privateKey), BigInt(p));
}

/**
 * Exponentiation modulaire rapide (a^b mod m)
 * Utilise l'algorithme d'exponentiation rapide par carrés successifs
 */
function modPow(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  
  let result = 1n;
  base = base % modulus;
  
  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exponent = exponent >> 1n;
    base = (base * base) % modulus;
  }
  
  return result;
}

/**
 * Simulateur complet d'échange Diffie-Hellman
 * Retourne les clés privées/publiques et la clé partagée
 */
function simulateDHExchange() {
  const { p, g } = DH_PARAMS;

  // Client génère sa paire
  const clientPrivate = generateDHPrivate();
  const clientPublic = computeDHPublic(g, clientPrivate, p);

  // Serveur génère sa paire
  const serverPrivate = generateDHPrivate();
  const serverPublic = computeDHPublic(g, serverPrivate, p);

  // Calcul des clés partagées (doivent être identiques)
  const clientShared = computeDHShared(serverPublic, clientPrivate, p);
  const serverShared = computeDHShared(clientPublic, serverPrivate, p);

  return {
    client: {
      private: clientPrivate.toString(16),
      public: clientPublic.toString(16),
      shared: clientShared.toString(16)
    },
    server: {
      private: serverPrivate.toString(16),
      public: serverPublic.toString(16),
      shared: serverShared.toString(16)
    },
    keysMatch: clientShared === serverShared,
    note: 'En production: ne JAMAIS logger les clés privées ou partagées!'
  };
}

// ============================================================================
// STOCKAGE SÉCURISÉ DE MOT DE PASSE: pbkdf2
// ============================================================================

/**
 * Hash un mot de passe avec pbkdf2 + salt
 * @param {string} password - Mot de passe en clair
 * @param {string} salt - Salt hexadécimal (généré si absent)
 * @param {number} iterations - Nombre d'itérations (défaut 200000)
 * @returns {Object} {salt, derived, iterations, keylen, digest}
 */
function hashPassword(password, salt = null, iterations = 200000) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const keylen = 64;
  const digest = 'sha512';

  const derived = crypto.pbkdf2Sync(
    password,
    salt,
    iterations,
    keylen,
    digest
  ).toString('hex');

  return {
    salt,
    derived,
    iterations,
    keylen,
    digest
  };
}

/**
 * Vérifie un mot de passe contre un enregistrement hashé
 * @param {string} password - Mot de passe à vérifier
 * @param {Object} record - Enregistrement {salt, derived, iterations, keylen, digest}
 * @returns {boolean} true si le mot de passe correspond
 */
function verifyPassword(password, record) {
  const derived = crypto.pbkdf2Sync(
    password,
    record.salt,
    record.iterations,
    record.keylen,
    record.digest
  ).toString('hex');

  return timingSafeEqual(derived, record.derived);
}

/**
 * Comparaison sécurisée contre les timing attacks
 */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(
    Buffer.from(a, 'hex'),
    Buffer.from(b, 'hex')
  );
}

// ============================================================================
// HMAC (Hash-based Message Authentication Code)
// ============================================================================

/**
 * Calcule un HMAC pour authentifier un message
 * @param {string} key - Clé secrète (peut être la clé de session DH)
 * @param {string} message - Message à authentifier
 * @param {string} algorithm - Algorithme de hash (défaut 'sha256')
 * @returns {string} HMAC en hexadécimal
 */
function computeHMAC(key, message, algorithm = 'sha256') {
  return crypto.createHmac(algorithm, key)
    .update(message)
    .digest('hex');
}

/**
 * Vérifie un HMAC
 * @param {string} key - Clé secrète
 * @param {string} message - Message original
 * @param {string} receivedHmac - HMAC reçu à vérifier
 * @param {string} algorithm - Algorithme de hash
 * @returns {boolean} true si le HMAC est valide
 */
function verifyHMAC(key, message, receivedHmac, algorithm = 'sha256') {
  const computed = computeHMAC(key, message, algorithm);
  return timingSafeEqual(computed, receivedHmac);
}

/**
 * Génère un nonce aléatoire (pour challenge-response)
 */
function generateNonce(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

// ============================================================================
// CHIFFREMENT SYMÉTRIQUE (AES-256-GCM) avec clé dérivée de DH
// ============================================================================

/**
 * Dérive une clé AES à partir de la clé partagée DH
 */
function deriveAESKey(sharedSecret) {
  // Utiliser HKDF ou pbkdf2 pour dériver une clé de taille fixe
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(
    sharedSecret.toString(),
    salt,
    10000,
    32, // 256 bits pour AES-256
    'sha256'
  );

  return { key, salt };
}

/**
 * Chiffre un message avec AES-256-GCM
 */
function encryptAES(plaintext, key) {
  const iv = crypto.randomBytes(12); // 96 bits pour GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return {
    ciphertext: encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

/**
 * Déchiffre un message AES-256-GCM
 */
function decryptAES(ciphertext, key, iv, authTag) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(iv, 'hex')
  );

  decipher.setAuthTag(Buffer.from(authTag, 'hex'));

  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  // Diffie-Hellman
  DH_PARAMS,
  generateDHPrivate,
  computeDHPublic,
  computeDHShared,
  simulateDHExchange,
  modPow,

  // Stockage mot de passe
  hashPassword,
  verifyPassword,

  // HMAC
  computeHMAC,
  verifyHMAC,
  generateNonce,

  // Chiffrement symétrique
  deriveAESKey,
  encryptAES,
  decryptAES
};

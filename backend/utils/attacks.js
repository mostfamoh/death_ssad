/**
 * attacks.js - Simulations d'attaques sur les algorithmes classiques
 * Brute-force (César, Affine), Dictionary attack, MitM simulation
 */

const ciphers = require('./ciphers');

// ============================================================================
// BRUTE-FORCE CÉSAR
// ============================================================================

/**
 * Teste toutes les 26 clés possibles pour César
 * @param {string} ciphertext - Texte chiffré
 * @returns {Array} Liste de {shift, text} pour tous les décalages
 */
function bruteForceCaesar(ciphertext) {
  const results = [];

  for (let shift = 0; shift < 26; shift++) {
    const decrypted = ciphers.caesarDecrypt(ciphertext, shift);
    results.push({
      shift,
      text: decrypted
    });
  }

  return results;
}

// ============================================================================
// BRUTE-FORCE AFFINE
// ============================================================================

/**
 * Teste toutes les combinaisons (a,b) valides pour Affine
 * a doit être premier avec 26: a ∈ {1,3,5,7,9,11,15,17,19,21,23,25}
 * b peut être 0..25
 * Total: 12 × 26 = 312 combinaisons
 */
function bruteForceAffine(ciphertext) {
  const validA = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
  const results = [];

  for (const a of validA) {
    for (let b = 0; b < 26; b++) {
      try {
        const decrypted = ciphers.affineDecrypt(ciphertext, a, b);
        results.push({
          a,
          b,
          text: decrypted
        });
      } catch (e) {
        // Ignore les erreurs
      }
    }
  }

  return results;
}

// ============================================================================
// BRUTE-FORCE MOT DE PASSE (alphabet limité)
// ============================================================================

/**
 * Génère toutes les combinaisons possibles pour un alphabet et longueur donnés
 * ATTENTION: Explosion combinatoire! Utiliser avec précaution.
 * @param {string} charset - Alphabet (ex: '0123456789' pour digits)
 * @param {number} length - Longueur du mot de passe
 * @param {number} maxAttempts - Limite de sécurité (défaut 10000)
 */
function bruteForcePassword(charset, length, maxAttempts = 10000) {
  const results = [];
  const total = Math.pow(charset.length, length);

  if (total > maxAttempts) {
    return {
      error: `Trop de combinaisons (${total}). Limité à ${maxAttempts} pour raisons de performance.`,
      total,
      maxAttempts
    };
  }

  function generate(current, depth) {
    if (results.length >= maxAttempts) return;

    if (depth === length) {
      results.push(current);
      return;
    }

    for (const char of charset) {
      generate(current + char, depth + 1);
    }
  }

  generate('', 0);

  return {
    total,
    generated: results.length,
    passwords: results
  };
}

// ============================================================================
// DICTIONARY ATTACK
// ============================================================================

/**
 * Compare les candidats déchiffrés avec un dictionnaire
 * @param {Array} candidates - Liste de {text, ...} candidats
 * @param {string} dictPath - Chemin vers le fichier dictionnaire
 * @returns {Array} Liste des matches trouvés
 */
function dictionaryAttack(candidates, dictPath) {
  const fs = require('fs');
  const words = fs.readFileSync(dictPath, 'utf8')
    .split('\n')
    .map(w => w.trim().toLowerCase())
    .filter(Boolean);

  const wordSet = new Set(words);
  const matches = [];

  for (const candidate of candidates) {
    const text = candidate.text.toLowerCase();
    if (wordSet.has(text)) {
      matches.push({
        ...candidate,
        matched: text
      });
    }
  }

  return matches;
}

/**
 * Attaque par dictionnaire directe: essaie de chiffrer chaque mot du dictionnaire
 * et compare avec le ciphertext
 * @param {string} ciphertext - Texte chiffré intercepté
 * @param {Array} words - Liste de mots du dictionnaire
 * @param {string} cipher - Type de chiffrement ('caesar', 'affine', etc.)
 * @param {Object} params - Paramètres du chiffrement (shift, a, b, etc.)
 */
function dictionaryDirectAttack(ciphertext, words, cipher, params) {
  const matches = [];

  for (const word of words) {
    let encrypted = '';

    try {
      switch (cipher) {
        case 'caesar':
          encrypted = ciphers.caesarEncrypt(word, params?.shift || 3);
          break;
        case 'affine':
          encrypted = ciphers.affineEncrypt(word, params?.a || 5, params?.b || 8);
          break;
        case 'playfair':
          encrypted = ciphers.playfairEncrypt(word, params?.key || 'SECRET');
          break;
        case 'hill':
          encrypted = ciphers.hillEncrypt(word, params?.keyMatrix || [[6,24,1],[13,16,10],[20,17,15]]);
          break;
        default:
          encrypted = word;
      }

      if (encrypted.toLowerCase() === ciphertext.toLowerCase()) {
        matches.push(word);
      }
    } catch (e) {
      // Ignore les erreurs (ex: Hill avec longueur inappropriée)
    }
  }

  return matches;
}

// ============================================================================
// SIMULATION MAN-IN-THE-MIDDLE (MitM)
// ============================================================================

/**
 * Simule une interception MitM du processus d'authentification
 * L'attaquant intercepte le ciphertext/payload envoyé au serveur
 * 
 * Scénarios simulés:
 * 1. Attaque offline (brute-force sur ciphertext intercepté)
 * 2. Replay attack (renvoyer le même ciphertext)
 * 3. MitM sur Diffie-Hellman (interception A et B, double échange)
 * 
 * @param {string} intercepted - Données interceptées
 * @param {Object} context - Contexte (type de cipher, params DH, etc.)
 */
function simulateMitM(intercepted, context = {}) {
  const report = {
    timestamp: new Date().toISOString(),
    intercepted,
    attacks: []
  };

  // 1. Tentative de brute-force offline
  if (context.cipher === 'caesar') {
    const startTime = Date.now();
    const candidates = bruteForceCaesar(intercepted);
    const elapsed = (Date.now() - startTime) / 1000;

    report.attacks.push({
      type: 'Offline Brute-Force (Caesar)',
      attempts: 26,
      elapsed: `${elapsed.toFixed(3)}s`,
      candidates: candidates.slice(0, 5), // Top 5
      note: 'Toutes les 26 clés testées instantanément'
    });
  }

  if (context.cipher === 'affine') {
    const startTime = Date.now();
    const candidates = bruteForceAffine(intercepted);
    const elapsed = (Date.now() - startTime) / 1000;

    report.attacks.push({
      type: 'Offline Brute-Force (Affine)',
      attempts: 312,
      elapsed: `${elapsed.toFixed(3)}s`,
      candidates: candidates.slice(0, 5),
      note: '312 combinaisons (12 valeurs de a × 26 valeurs de b)'
    });
  }

  // 2. Replay attack
  report.attacks.push({
    type: 'Replay Attack',
    payload: intercepted,
    vulnerability: 'Si le serveur accepte le même ciphertext sans nonce/session ID, l\'attaquant peut usurper l\'identité',
    mitigation: 'Utiliser un challenge-response avec nonce aléatoire'
  });

  // 3. MitM sur Diffie-Hellman (si applicable)
  if (context.dhPublic) {
    report.attacks.push({
      type: 'Man-in-the-Middle sur Diffie-Hellman',
      clientPublic: context.dhPublic,
      vulnerability: 'Sans authentification des parties (signatures, certificats), un attaquant peut:\n' +
                     '  1. Intercepter A (client→serveur)\n' +
                     '  2. Générer sa propre paire (a\', A\')\n' +
                     '  3. Envoyer A\' au serveur\n' +
                     '  4. Intercepter B (serveur→client)\n' +
                     '  5. Envoyer B\' au client\n' +
                     '  → L\'attaquant déchiffre tout le trafic',
      mitigation: 'Utiliser authenticated Diffie-Hellman (signatures RSA/ECDSA) ou protocoles comme TLS 1.3'
    });
  }

  return report;
}

// ============================================================================
// ANALYSE DE FRÉQUENCE (bonus)
// ============================================================================

/**
 * Analyse la fréquence des lettres dans un texte (aide pour cryptanalyse)
 */
function frequencyAnalysis(text) {
  const freq = {};
  let total = 0;

  for (const char of text.toUpperCase()) {
    if (char >= 'A' && char <= 'Z') {
      freq[char] = (freq[char] || 0) + 1;
      total++;
    }
  }

  const sorted = Object.entries(freq)
    .map(([char, count]) => ({
      char,
      count,
      percentage: ((count / total) * 100).toFixed(2)
    }))
    .sort((a, b) => b.count - a.count);

  return {
    total,
    distribution: sorted,
    note: 'En français: E(14.7%), A(8.1%), S(7.9%), I(7.5%), T(7.2%), N(7.1%), R(6.6%), U(6.3%), L(5.5%), O(5.4%)'
  };
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  bruteForceCaesar,
  bruteForceAffine,
  bruteForcePassword,
  dictionaryAttack,
  dictionaryDirectAttack,
  simulateMitM,
  frequencyAnalysis
};

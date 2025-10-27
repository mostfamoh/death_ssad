/**
 * app.js - Frontend Logic (Vanilla JavaScript)
 * Gestion des formulaires, appels API, Diffie-Hellman client, affichage résultats
 */

const API_BASE = 'http://localhost:3000';

// ============================================================================
// UTILITAIRES
// ============================================================================

/**
 * Affiche une alerte Bootstrap
 */
function showAlert(message, type = 'info') {
  const alertZone = document.getElementById('alert-zone');
  const alert = document.createElement('div');
  alert.className = `alert alert-${type} alert-dismissible fade show`;
  alert.innerHTML = `
    ${message}
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
  `;
  alertZone.appendChild(alert);

  setTimeout(() => alert.remove(), 5000);
}

/**
 * Effectue une requête API
 */
async function apiRequest(endpoint, method = 'GET', body = null) {
  const options = {
    method,
    headers: {
      'Content-Type': 'application/json'
    }
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(`${API_BASE}${endpoint}`, options);
    const data = await response.json();
    return { ok: response.ok, data };
  } catch (error) {
    console.error('API Error:', error);
    return { ok: false, error: error.message };
  }
}

// ============================================================================
// DIFFIE-HELLMAN CLIENT
// ============================================================================

const DH_PARAMS = {
  p: BigInt('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'),
  g: BigInt(2)
};

/**
 * Génère un exposant privé aléatoire
 */
function generateDHPrivate(bits = 128) {
  const bytes = Math.ceil(bits / 8);
  const randomArray = new Uint8Array(bytes);
  crypto.getRandomValues(randomArray);
  
  let hex = '';
  for (const byte of randomArray) {
    hex += byte.toString(16).padStart(2, '0');
  }
  
  return BigInt('0x' + hex);
}

/**
 * Calcule la clé publique: g^private mod p
 */
function computeDHPublic(g, privateKey, p) {
  return modPow(g, privateKey, p);
}

/**
 * Calcule la clé partagée: otherPublic^private mod p
 */
function computeDHShared(otherPublic, privateKey, p) {
  return modPow(otherPublic, privateKey, p);
}

/**
 * Exponentiation modulaire rapide
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
 * Échange Diffie-Hellman complet avec le serveur
 */
async function performDHExchange() {
  const { p, g } = DH_PARAMS;
  
  // Client génère sa paire
  const clientPrivate = generateDHPrivate();
  const clientPublic = computeDHPublic(g, clientPrivate, p);

  // Envoyer clientPublic au serveur
  const response = await apiRequest('/dh', 'POST', {
    clientPublic: clientPublic.toString(),
    p: p.toString(),
    g: g.toString()
  });

  if (!response.ok) {
    throw new Error('Échec de l\'échange DH');
  }

  const serverPublic = BigInt(response.data.serverPublic);
  
  // Calculer la clé partagée
  const sharedKey = computeDHShared(serverPublic, clientPrivate, p);

  return {
    clientPublic: clientPublic.toString(16),
    serverPublic: serverPublic.toString(16),
    sharedKey: sharedKey.toString(16)
  };
}

// ============================================================================
// GESTION DES PARAMÈTRES DE CHIFFREMENT
// ============================================================================

// Afficher/masquer les paramètres selon l'algorithme choisi
document.addEventListener('DOMContentLoaded', () => {
  const modeSelect = document.getElementById('reg-mode');
  const cipherSelect = document.getElementById('reg-cipher');
  const cipherSelection = document.getElementById('cipher-selection');

  modeSelect.addEventListener('change', () => {
    cipherSelection.style.display = modeSelect.value === 'weak' ? 'block' : 'none';
    updateCipherParams();
  });

  cipherSelect.addEventListener('change', updateCipherParams);

  function updateCipherParams() {
    const mode = modeSelect.value;
    const cipher = cipherSelect.value;
    
    document.querySelectorAll('.cipher-params').forEach(el => el.style.display = 'none');
    
    if (mode === 'weak') {
      document.getElementById(`params-${cipher}`).style.display = 'block';
    }
  }

  // Initialisation
  cipherSelection.style.display = modeSelect.value === 'weak' ? 'block' : 'none';
  updateCipherParams();
});

// ============================================================================
// INSCRIPTION
// ============================================================================

document.getElementById('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = document.getElementById('reg-username').value;
  const password = document.getElementById('reg-password').value;
  const mode = document.getElementById('reg-mode').value;
  const cipher = document.getElementById('reg-cipher').value;

  let params = {};
  
  if (mode === 'weak') {
    switch (cipher) {
      case 'caesar':
        params.shift = parseInt(document.getElementById('caesar-shift').value);
        break;
      case 'affine':
        params.a = parseInt(document.getElementById('affine-a').value);
        params.b = parseInt(document.getElementById('affine-b').value);
        break;
      case 'playfair':
        params.key = document.getElementById('playfair-key').value;
        break;
      case 'hill':
        params.keyMatrix = [[6,24,1],[13,16,10],[20,17,15]];
        break;
    }
  }

  const result = await apiRequest('/register', 'POST', {
    username,
    password,
    mode,
    cipher,
    params
  });

  const resultDiv = document.getElementById('register-result');

  if (result.ok && result.data.ok) {
    resultDiv.innerHTML = `
      <div class="alert alert-success">
        <strong>✓ Inscription réussie!</strong><br>
        ${result.data.note}<br>
        ${mode === 'weak' ? `<small>Stocké: <code>${result.data.stored}</code></small>` : ''}
      </div>
    `;
    showAlert('Compte créé avec succès!', 'success');
    document.getElementById('register-form').reset();
  } else {
    resultDiv.innerHTML = `
      <div class="alert alert-danger">
        <strong>✗ Erreur:</strong> ${result.data?.error || result.error || 'Échec de l\'inscription'}
      </div>
    `;
    showAlert('Échec de l\'inscription', 'danger');
  }
});

// ============================================================================
// CONNEXION
// ============================================================================

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;
  const useDH = document.getElementById('use-dh').checked;

  let sessionKey = null;

  if (useDH) {
    showAlert('Échange Diffie-Hellman en cours...', 'info');
    
    try {
      const dhResult = await performDHExchange();
      sessionKey = dhResult.sharedKey;
      
      showAlert(`✓ Clé de session établie: ${sessionKey.substring(0, 16)}...`, 'success');
    } catch (error) {
      showAlert('Échec de l\'échange DH: ' + error.message, 'danger');
      return;
    }
  }

  // Récupérer les infos utilisateur pour le mode weak
  const userInfoResult = await apiRequest(`/user/${username}`, 'GET');
  
  let loginPayload = {
    username,
    payload: password,
    payloadType: 'plaintext',
    sessionKey
  };

  // Si mode weak, ajouter cipher et params
  if (userInfoResult.ok && userInfoResult.data.mode === 'weak') {
    loginPayload.cipher = userInfoResult.data.cipher;
    loginPayload.params = userInfoResult.data.params;
  }

  const result = await apiRequest('/login', 'POST', loginPayload);

  const resultDiv = document.getElementById('login-result');

  if (result.ok && result.data.success) {
    resultDiv.innerHTML = `
      <div class="alert alert-success">
        <strong>✓ Authentification réussie!</strong><br>
        Bienvenue, <strong>${username}</strong>
        ${useDH ? '<br><small class="text-muted">Connexion sécurisée via Diffie-Hellman</small>' : ''}
      </div>
    `;
    showAlert('Connexion réussie!', 'success');
  } else {
    resultDiv.innerHTML = `
      <div class="alert alert-danger">
        <strong>✗ Échec de l'authentification</strong><br>
        ${result.data?.message || 'Identifiants incorrects'}
      </div>
    `;
    showAlert('Échec de la connexion', 'danger');
  }
});

// ============================================================================
// OUTILS DE CHIFFREMENT/DÉCHIFFREMENT
// ============================================================================

/**
 * Applique un algorithme de chiffrement côté client (démonstration)
 * En pratique, ces fonctions sont implémentées côté serveur
 */
async function toolCipher(cipher, operation) {
  let text, result;

  switch (cipher) {
    case 'caesar':
      text = document.getElementById('caesar-text').value;
      const shift = parseInt(document.getElementById('caesar-tool-shift').value);
      result = caesarClient(text, operation === 'encrypt' ? shift : -shift);
      document.getElementById('caesar-result').innerHTML = displayResult(result);
      break;

    case 'affine':
      text = document.getElementById('affine-text').value;
      const a = parseInt(document.getElementById('affine-tool-a').value);
      const b = parseInt(document.getElementById('affine-tool-b').value);
      try {
        result = affineClient(text, a, b, operation);
        document.getElementById('affine-result').innerHTML = displayResult(result);
      } catch (e) {
        document.getElementById('affine-result').innerHTML = `<div class="alert alert-danger">${e.message}</div>`;
      }
      break;

    case 'playfair':
      text = document.getElementById('playfair-text').value;
      const key = document.getElementById('playfair-tool-key').value;
      result = `[Playfair ${operation} - implémentation complexe, voir serveur]`;
      document.getElementById('playfair-result').innerHTML = displayResult(result);
      showAlert('Playfair: implémentation complète côté serveur', 'info');
      break;

    case 'hill':
      text = document.getElementById('hill-text').value;
      result = `[Hill 3×3 ${operation} - implémentation matricielle, voir serveur]`;
      document.getElementById('hill-result').innerHTML = displayResult(result);
      showAlert('Hill: implémentation complète côté serveur', 'info');
      break;
  }
}

/**
 * César client (démo)
 */
function caesarClient(text, shift) {
  return text.split('').map(ch => {
    if (ch >= 'a' && ch <= 'z') {
      return String.fromCharCode((ch.charCodeAt(0) - 97 + shift + 26) % 26 + 97);
    }
    if (ch >= 'A' && ch <= 'Z') {
      return String.fromCharCode((ch.charCodeAt(0) - 65 + shift + 26) % 26 + 65);
    }
    return ch;
  }).join('');
}

/**
 * Affine client (démo)
 */
function affineClient(text, a, b, operation) {
  function gcd(x, y) {
    while (y) [x, y] = [y, x % y];
    return x;
  }

  function modInverse(a, m) {
    for (let x = 1; x < m; x++) {
      if ((a * x) % m === 1) return x;
    }
    return null;
  }

  if (gcd(a, 26) !== 1) {
    throw new Error(`'a' (${a}) doit être premier avec 26`);
  }

  if (operation === 'decrypt') {
    const aInv = modInverse(a, 26);
    if (!aInv) throw new Error(`Impossible de calculer l'inverse de ${a}`);
    a = aInv;
    b = -b;
  }

  return text.split('').map(ch => {
    if (ch >= 'a' && ch <= 'z') {
      const x = ch.charCodeAt(0) - 97;
      const y = ((a * x + b) % 26 + 26) % 26;
      return String.fromCharCode(y + 97);
    }
    if (ch >= 'A' && ch <= 'Z') {
      const x = ch.charCodeAt(0) - 65;
      const y = ((a * x + b) % 26 + 26) % 26;
      return String.fromCharCode(y + 65);
    }
    return ch;
  }).join('');
}

function displayResult(text) {
  return `
    <div class="alert alert-info">
      <strong>Résultat:</strong><br>
      <code>${text}</code>
      <button class="btn btn-sm btn-outline-secondary float-end" onclick="navigator.clipboard.writeText('${text}')">
        <i class="bi bi-clipboard"></i> Copier
      </button>
    </div>
  `;
}

// ============================================================================
// SIMULATION D'ATTAQUES
// ============================================================================

// Show/hide Playfair key input
document.getElementById('attack-cipher').addEventListener('change', (e) => {
  const playfairParams = document.getElementById('attack-playfair-params');
  playfairParams.style.display = e.target.value === 'playfair' ? 'block' : 'none';
});

// Generate detailed step-by-step attack explanation
function generateAttackSteps(cipher, intercepted, attackType) {
  const steps = [];
  
  if (attackType === 'bruteforce' || attackType === 'all') {
    switch (cipher) {
      case 'caesar':
        steps.push({
          title: '🔍 Étape 1: Brute-Force César',
          content: `
            <p><strong>Principe:</strong> Tester tous les décalages possibles (0-25)</p>
            <p><strong>Ciphertext intercepté:</strong> <code>${intercepted}</code></p>
            <ol>
              <li>Pour shift = 0: Déchiffrer "${intercepted}"</li>
              <li>Pour shift = 1: Déchiffrer "${intercepted}"</li>
              <li>...</li>
              <li>Pour shift = 25: Déchiffrer "${intercepted}"</li>
            </ol>
            <p><strong>Total tentatives:</strong> 26</p>
            <p><strong>Complexité:</strong> O(26) = Triviale</p>
          `
        });
        break;
        
      case 'affine':
        steps.push({
          title: '🔍 Étape 1: Brute-Force Affine',
          content: `
            <p><strong>Principe:</strong> Tester toutes les combinaisons (a, b) valides</p>
            <p><strong>Formule:</strong> P = a<sup>-1</sup> × (C - b) mod 26</p>
            <p><strong>Valeurs de a:</strong> {1,3,5,7,9,11,15,17,19,21,23,25} (premiers avec 26)</p>
            <p><strong>Valeurs de b:</strong> 0 à 25</p>
            <p><strong>Total combinaisons:</strong> 12 × 26 = 312</p>
            <p><strong>Complexité:</strong> O(312) = Très faible</p>
          `
        });
        break;
        
      case 'playfair':
        steps.push({
          title: '🔍 Étape 1: Analyse Playfair',
          content: `
            <p><strong>Principe:</strong> Playfair nécessite la clé pour déchiffrer</p>
            <p><strong>Ciphertext:</strong> <code>${intercepted}</code></p>
            <p><strong>Stratégies d'attaque:</strong></p>
            <ul>
              <li>Si clé connue: Déchiffrement direct</li>
              <li>Sinon: Essayer clés courantes (password, secret, key, etc.)</li>
              <li>Analyse de fréquence des digrammes</li>
              <li>Known-plaintext attack si texte connu</li>
            </ul>
            <p><strong>Complexité:</strong> Dépend de l'espace de clés testé</p>
          `
        });
        break;
        
      case 'hill':
        steps.push({
          title: '🔍 Étape 1: Analyse Hill 3×3',
          content: `
            <p><strong>Principe:</strong> Hill nécessite la matrice clé pour déchiffrer</p>
            <p><strong>Attaque possible:</strong> Known-plaintext attack</p>
            <ul>
              <li>Si 3 blocs plaintext/ciphertext connus</li>
              <li>Résoudre système: C = K × P mod 26</li>
              <li>Trouver K puis K<sup>-1</sup></li>
            </ul>
            <p><strong>Complexité:</strong> O(26<sup>9</sup>) brute-force impraticable</p>
            <p><strong>Note:</strong> Vulnérable si plaintext connu</p>
          `
        });
        break;
    }
  }
  
  if (attackType === 'dictionary' || attackType === 'all') {
    steps.push({
      title: '📖 Étape 2: Dictionary Attack',
      content: `
        <p><strong>Principe:</strong> Comparer contre un dictionnaire de mots courants</p>
        <ol>
          <li>Charger dictionnaire (dict_small.txt)</li>
          <li>Pour chaque mot du dictionnaire:</li>
          <ul>
            <li>Chiffrer le mot avec l'algorithme cible</li>
            <li>Comparer avec ciphertext intercepté</li>
            <li>Si match → mot de passe trouvé ✓</li>
          </ul>
          <li>Afficher les correspondances</li>
        </ol>
        <p><strong>Efficacité:</strong> Très élevée si password faible/commun</p>
        <p><strong>Défense:</strong> Utiliser mots de passe longs et complexes</p>
      `
    });
  }
  
  if (attackType === 'mitm' || attackType === 'all') {
    steps.push({
      title: '🕵️ Étape 3: Man-in-the-Middle (MitM)',
      content: `
        <p><strong>Scénario d'attaque:</strong></p>
        <div class="bg-light p-3 rounded">
          <pre>
Client → [Attaquant] → Serveur

1. Client envoie: username + ciphertext
2. Attaquant intercepte le ciphertext
3. Attaquant effectue brute-force OFFLINE
4. Attaquant récupère le plaintext
5. Attaquant peut:
   - Se connecter avec le vrai mot de passe
   - Effectuer un replay attack
   - Compromettre le compte
          </pre>
        </div>
        <p><strong>Vulnérabilités exposées:</strong></p>
        <ul>
          <li>❌ Pas de nonce/session ID</li>
          <li>❌ Ciphertext réutilisable (replay)</li>
          <li>❌ Pas de TLS/chiffrement transport</li>
          <li>❌ Algorithme faible facilement cassé</li>
        </ul>
        <p><strong>Protections nécessaires:</strong></p>
        <ul>
          <li>✅ TLS 1.3 pour le transport</li>
          <li>✅ Challenge-response avec nonce</li>
          <li>✅ pbkdf2/Argon2 pour stockage</li>
          <li>✅ Rate-limiting contre brute-force</li>
        </ul>
      `
    });
  }
  
  return steps;
}

document.getElementById('attack-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = document.getElementById('attack-username').value;
  const intercepted = document.getElementById('attack-intercepted').value;
  const cipher = document.getElementById('attack-cipher').value;
  const attackType = document.getElementById('attack-type').value;
  const showSteps = document.getElementById('show-steps').checked;
  const playfairKey = document.getElementById('attack-playfair-key').value;

  const progressDiv = document.getElementById('attack-progress');
  const progressText = document.getElementById('progress-text');
  const resultDiv = document.getElementById('attack-result');

  // Show progress
  progressDiv.style.display = 'block';
  progressText.textContent = 'Initialisation de l\'attaque...';
  resultDiv.innerHTML = '';

  // Build params
  const params = {};
  if (cipher === 'playfair' && playfairKey) {
    params.key = playfairKey;
  }

  // Simulate progress
  await new Promise(resolve => setTimeout(resolve, 300));
  progressText.textContent = 'Exécution des attaques...';

  const result = await apiRequest('/simulate/mitm', 'POST', {
    username,
    intercepted,
    cipher,
    params,
    attackType
  });

  progressDiv.style.display = 'none';

  if (result.ok) {
    let html = '';
    
    // Show detailed steps if requested
    if (showSteps) {
      const steps = generateAttackSteps(cipher, intercepted, attackType);
      html += `
        <div class="card border-info mb-4">
          <div class="card-header bg-info text-white">
            <h5>📚 Étapes Détaillées de l'Attaque</h5>
          </div>
          <div class="card-body">
      `;
      
      for (const step of steps) {
        html += `
          <div class="mb-4">
            <h6 class="text-primary">${step.title}</h6>
            ${step.content}
          </div>
          ${steps.indexOf(step) < steps.length - 1 ? '<hr>' : ''}
        `;
      }
      
      html += `
          </div>
        </div>
      `;
    }
    
    // Show attack results
    html += `
      <div class="card border-warning">
        <div class="card-header bg-warning">
          <h5>📊 Résultats de l'Attaque</h5>
        </div>
        <div class="card-body">
          <p><strong>🎯 Utilisateur cible:</strong> ${result.data.username}</p>
          <p><strong>📦 Données interceptées:</strong> <code class="fs-5">${result.data.intercepted}</code></p>
          <p><strong>🔐 Algorithme:</strong> ${cipher.toUpperCase()}</p>
          <hr>
    `;

    for (const attack of result.data.attacks) {
      html += `
        <div class="mb-4">
          <h6 class="text-danger"><i class="bi bi-shield-x"></i> ${attack.type}</h6>
          <div class="row">
            <div class="col-md-4">
              <div class="card bg-light">
                <div class="card-body">
                  <small class="text-muted">Tentatives</small>
                  <h4 class="mb-0">${attack.attempts}</h4>
                </div>
              </div>
            </div>
            <div class="col-md-4">
              <div class="card bg-light">
                <div class="card-body">
                  <small class="text-muted">Temps écoulé</small>
                  <h4 class="mb-0">${attack.elapsed}s</h4>
                </div>
              </div>
            </div>
            <div class="col-md-4">
              <div class="card ${attack.success ? 'bg-danger' : 'bg-secondary'} text-white">
                <div class="card-body">
                  <small>Succès</small>
                  <h4 class="mb-0">${attack.success ? '✓ OUI' : '✗ NON'}</h4>
                </div>
              </div>
            </div>
          </div>
      `;
      
      if (attack.recovered) {
        html += `
          <div class="alert alert-danger mt-3">
            <i class="bi bi-unlock-fill"></i> <strong>MOT DE PASSE RÉCUPÉRÉ:</strong>
            <h3 class="mt-2 mb-0"><code>${attack.recovered}</code></h3>
            <small>⚠️ Le compte est complètement compromis!</small>
          </div>
        `;
      }

      if (attack.candidates && attack.candidates.length > 0) {
        html += `
          <details class="mt-3">
            <summary class="btn btn-sm btn-outline-secondary">
              <i class="bi bi-list"></i> Voir tous les candidats (${attack.candidates.length})
            </summary>
            <div class="table-responsive mt-2">
              <table class="table table-sm table-striped">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Texte Déchiffré</th>
                    <th>Paramètres</th>
                  </tr>
                </thead>
                <tbody>
        `;
        attack.candidates.slice(0, 15).forEach((c, i) => {
          const params = c.shift !== undefined ? `shift=${c.shift}` : 
                        c.a !== undefined ? `a=${c.a}, b=${c.b}` : 'N/A';
          html += `
            <tr>
              <td>${i+1}</td>
              <td><code>${c.text}</code></td>
              <td><small class="text-muted">${params}</small></td>
            </tr>
          `;
        });
        html += `
                </tbody>
              </table>
            </div>
          </details>
        `;
      }

      if (attack.matches && attack.matches.length > 0) {
        html += `
          <div class="alert alert-warning mt-3">
            <strong><i class="bi bi-book"></i> Correspondances dictionnaire:</strong>
            ${attack.matches.map(m => `<code class="ms-2">${m}</code>`).join(', ')}
          </div>
        `;
      }

      if (attack.vulnerability) {
        html += `<div class="alert alert-danger mt-3"><strong>🚨 Vulnérabilité:</strong><br>${attack.vulnerability}</div>`;
      }

      if (attack.mitigation) {
        html += `<div class="alert alert-success mt-3"><strong>🛡️ Protection:</strong><br>${attack.mitigation}</div>`;
      }

      html += '</div><hr>';
    }

    html += '</div></div>';
    resultDiv.innerHTML = html;
    showAlert('✅ Attaque simulée avec succès!', 'success');
  } else {
    resultDiv.innerHTML = `
      <div class="alert alert-danger">
        <strong>❌ Erreur:</strong> ${result.data?.error || result.error}
      </div>
    `;
    showAlert('Échec de la simulation', 'danger');
  }
});

/**
 * Télécharge le fichier results.csv
 */
function downloadResults() {
  window.open(`${API_BASE}/results.csv`, '_blank');
  showAlert('Téléchargement du fichier results.csv...', 'info');
}

// ============================================================================
// INITIALISATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
  console.log('🔐 Application de cryptographie classique chargée');
  console.log('📡 API Backend:', API_BASE);
  
  showAlert('Bienvenue! Explorez les algorithmes classiques et leurs vulnérabilités.', 'info');
});

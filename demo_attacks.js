/**
 * Script de démonstration automatique des attaques
 * Lance plusieurs scénarios et génère un rapport
 */

const http = require('http');

const API_BASE = 'http://localhost:3000';

// Fonction pour faire des requêtes HTTP
function apiRequest(endpoint, method, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, API_BASE);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: method,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          resolve({ ok: res.statusCode === 200, data: JSON.parse(data) });
        } catch (e) {
          resolve({ ok: false, error: e.message });
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// Scénarios de test
const scenarios = [
  {
    name: "Attaque César Simple",
    user: {
      username: "demo_cesar",
      password: "hello",
      mode: "weak",
      cipher: "caesar",
      params: { shift: 3 }
    },
    attack: {
      cipher: "caesar"
    }
  },
  {
    name: "Attaque Affine",
    user: {
      username: "demo_affine",
      password: "attack",
      mode: "weak",
      cipher: "affine",
      params: { a: 5, b: 8 }
    },
    attack: {
      cipher: "affine"
    }
  },
  {
    name: "Dictionary Attack",
    user: {
      username: "demo_dict",
      password: "password",
      mode: "weak",
      cipher: "caesar",
      params: { shift: 7 }
    },
    attack: {
      cipher: "caesar"
    }
  }
];

// Fonction principale
async function runDemo() {
  console.log('\n╔═══════════════════════════════════════════════════════════╗');
  console.log('║  🎯 DÉMONSTRATION AUTOMATIQUE DES ATTAQUES              ║');
  console.log('╚═══════════════════════════════════════════════════════════╝\n');

  for (const scenario of scenarios) {
    console.log(`\n📌 ${scenario.name}`);
    console.log('─'.repeat(60));

    // 1. Créer le compte
    console.log('1️⃣  Création du compte...');
    const registerResult = await apiRequest('/register', 'POST', scenario.user);
    
    if (!registerResult.ok || !registerResult.data.ok) {
      console.log('   ⚠️  Utilisateur existe déjà ou erreur');
    } else {
      console.log(`   ✅ Compte créé: ${scenario.user.username}`);
      console.log(`   📦 Stocké: ${registerResult.data.stored}`);
    }

    // 2. Récupérer le ciphertext stocké
    const userInfoResult = await apiRequest(`/user/${scenario.user.username}`, 'GET');
    if (!userInfoResult.ok) {
      console.log('   ❌ Impossible de récupérer les infos utilisateur');
      continue;
    }

    // Pour obtenir le ciphertext, on doit le récupérer du fichier users.json
    // Simulons avec le ciphertext attendu
    const ciphers = require('./backend/utils/ciphers');
    let intercepted = '';
    
    try {
      switch (scenario.user.cipher) {
        case 'caesar':
          intercepted = ciphers.caesarEncrypt(scenario.user.password, scenario.user.params.shift);
          break;
        case 'affine':
          intercepted = ciphers.affineEncrypt(scenario.user.password, scenario.user.params.a, scenario.user.params.b);
          break;
      }
    } catch (e) {
      console.log('   ❌ Erreur de chiffrement:', e.message);
      continue;
    }

    console.log(`   🎯 Ciphertext intercepté: ${intercepted}`);

    // 3. Lancer l'attaque
    console.log('\n2️⃣  Lancement de l\'attaque MitM...');
    const attackResult = await apiRequest('/simulate/mitm', 'POST', {
      username: scenario.user.username,
      intercepted: intercepted,
      cipher: scenario.attack.cipher,
      params: scenario.user.params
    });

    if (attackResult.ok) {
      console.log('   ✅ Attaque terminée!\n');
      
      // Afficher les résultats
      for (const attack of attackResult.data.attacks) {
        console.log(`   📊 ${attack.type}:`);
        console.log(`      • Tentatives: ${attack.attempts}`);
        console.log(`      • Temps: ${attack.elapsed}s`);
        console.log(`      • Succès: ${attack.success ? '✅ OUI' : '❌ Non'}`);
        if (attack.recovered) {
          console.log(`      • 🔓 Mot de passe récupéré: "${attack.recovered}"`);
        }
        console.log('');
      }
    } else {
      console.log('   ❌ Échec de l\'attaque');
    }

    console.log('─'.repeat(60));
  }

  console.log('\n✅ Démonstration terminée!');
  console.log('📄 Consultez results.csv pour les détails complets\n');
}

// Exécution
runDemo().catch(err => {
  console.error('❌ Erreur:', err.message);
  process.exit(1);
});

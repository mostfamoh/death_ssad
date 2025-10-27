/**
 * Script pour décoder le mot de passe de bellia
 */

const ciphers = require('./backend/utils/ciphers');

const ciphertext = 'BGGNNWNW';
const key = 'key';

try {
  const plaintext = ciphers.playfairDecrypt(ciphertext, key);
  console.log('\n✅ Mot de passe déchiffré:');
  console.log('Ciphertext:', ciphertext);
  console.log('Clé Playfair:', key);
  console.log('→ Plaintext:', plaintext);
  console.log('\n📝 Utilisez ce mot de passe pour vous connecter avec "bellia"\n');
} catch (error) {
  console.error('❌ Erreur:', error.message);
}

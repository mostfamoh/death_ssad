/**
 * ciphers.js - Implémentations des algorithmes de chiffrement classiques
 * César, Affine, Playfair, Hill 3×3
 */

// ============================================================================
// UTILITAIRES MATHÉMATIQUES
// ============================================================================

/**
 * PGCD (Plus Grand Commun Diviseur) - Algorithme d'Euclide
 */
function gcd(a, b) {
  while (b !== 0) {
    [a, b] = [b, a % b];
  }
  return a;
}

/**
 * Inverse modulaire via algorithme d'Euclide étendu
 * Retourne x tel que (a * x) ≡ 1 (mod m)
 */
function modInverse(a, m) {
  a = ((a % m) + m) % m;
  for (let x = 1; x < m; x++) {
    if ((a * x) % m === 1) return x;
  }
  return null;
}

/**
 * Modulo positif (JavaScript % peut retourner négatif)
 */
function mod(n, m) {
  return ((n % m) + m) % m;
}

// ============================================================================
// CHIFFREMENT CÉSAR
// ============================================================================

/**
 * Chiffre un texte avec César (décalage alphabétique)
 * @param {string} text - Texte à chiffrer
 * @param {number} shift - Décalage (0-25)
 * @returns {string} Texte chiffré
 */
function caesarEncrypt(text, shift) {
  return text.split('').map(ch => {
    if (ch >= 'a' && ch <= 'z') {
      return String.fromCharCode(mod(ch.charCodeAt(0) - 97 + shift, 26) + 97);
    }
    if (ch >= 'A' && ch <= 'Z') {
      return String.fromCharCode(mod(ch.charCodeAt(0) - 65 + shift, 26) + 65);
    }
    return ch; // Caractères non-alphabétiques inchangés
  }).join('');
}

/**
 * Déchiffre un texte César
 */
function caesarDecrypt(text, shift) {
  return caesarEncrypt(text, -shift);
}

// ============================================================================
// CHIFFREMENT AFFINE
// ============================================================================

/**
 * Chiffre avec Affine: C = (a*P + b) mod 26
 * @param {string} text - Texte à chiffrer
 * @param {number} a - Coefficient multiplicatif (gcd(a,26)=1)
 * @param {number} b - Décalage additif
 */
function affineEncrypt(text, a, b) {
  if (gcd(a, 26) !== 1) {
    throw new Error(`Affine: 'a' (${a}) doit être premier avec 26. gcd(${a},26)=${gcd(a, 26)}`);
  }

  return text.split('').map(ch => {
    if (ch >= 'a' && ch <= 'z') {
      const x = ch.charCodeAt(0) - 97;
      const y = mod(a * x + b, 26);
      return String.fromCharCode(y + 97);
    }
    if (ch >= 'A' && ch <= 'Z') {
      const x = ch.charCodeAt(0) - 65;
      const y = mod(a * x + b, 26);
      return String.fromCharCode(y + 65);
    }
    return ch;
  }).join('');
}

/**
 * Déchiffre Affine: P = a_inv * (C - b) mod 26
 */
function affineDecrypt(text, a, b) {
  const aInv = modInverse(a, 26);
  if (aInv === null) {
    throw new Error(`Affine: impossible de calculer l'inverse de ${a} modulo 26`);
  }

  return text.split('').map(ch => {
    if (ch >= 'a' && ch <= 'z') {
      const y = ch.charCodeAt(0) - 97;
      const x = mod(aInv * (y - b), 26);
      return String.fromCharCode(x + 97);
    }
    if (ch >= 'A' && ch <= 'Z') {
      const y = ch.charCodeAt(0) - 65;
      const x = mod(aInv * (y - b), 26);
      return String.fromCharCode(x + 65);
    }
    return ch;
  }).join('');
}

// ============================================================================
// CHIFFREMENT PLAYFAIR
// ============================================================================

/**
 * Génère la matrice 5×5 Playfair à partir d'une clé
 * I et J sont fusionnés
 */
function buildPlayfairMatrix(key) {
  const alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'; // I/J fusionnés
  const seen = new Set();
  const matrix = [];

  // Ajouter les lettres de la clé (sans doublons)
  const keyUpper = key.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
  for (const ch of keyUpper) {
    if (!seen.has(ch)) {
      matrix.push(ch);
      seen.add(ch);
    }
  }

  // Ajouter le reste de l'alphabet
  for (const ch of alphabet) {
    if (!seen.has(ch)) {
      matrix.push(ch);
      seen.add(ch);
    }
  }

  // Convertir en matrice 5×5
  const grid = [];
  for (let i = 0; i < 5; i++) {
    grid.push(matrix.slice(i * 5, (i + 1) * 5));
  }

  return grid;
}

/**
 * Trouve la position d'un caractère dans la matrice Playfair
 */
function findPosition(matrix, char) {
  for (let row = 0; row < 5; row++) {
    for (let col = 0; col < 5; col++) {
      if (matrix[row][col] === char) {
        return [row, col];
      }
    }
  }
  return null;
}

/**
 * Prépare le texte pour Playfair (digrams avec padding)
 */
function preparePlayfairText(text) {
  text = text.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
  const digrams = [];
  let i = 0;

  while (i < text.length) {
    let a = text[i];
    let b = (i + 1 < text.length) ? text[i + 1] : 'X';

    if (a === b) {
      digrams.push(a + 'X');
      i++;
    } else {
      digrams.push(a + b);
      i += 2;
    }
  }

  return digrams;
}

/**
 * Chiffre un texte avec Playfair
 */
function playfairEncrypt(text, key) {
  const matrix = buildPlayfairMatrix(key);
  const digrams = preparePlayfairText(text);
  let result = '';

  for (const digram of digrams) {
    const [row1, col1] = findPosition(matrix, digram[0]);
    const [row2, col2] = findPosition(matrix, digram[1]);

    if (row1 === row2) {
      // Même ligne: décaler à droite
      result += matrix[row1][(col1 + 1) % 5];
      result += matrix[row2][(col2 + 1) % 5];
    } else if (col1 === col2) {
      // Même colonne: décaler en bas
      result += matrix[(row1 + 1) % 5][col1];
      result += matrix[(row2 + 1) % 5][col2];
    } else {
      // Rectangle: échanger colonnes
      result += matrix[row1][col2];
      result += matrix[row2][col1];
    }
  }

  return result;
}

/**
 * Déchiffre un texte Playfair
 */
function playfairDecrypt(text, key) {
  const matrix = buildPlayfairMatrix(key);
  text = text.toUpperCase().replace(/[^A-Z]/g, '');
  let result = '';

  for (let i = 0; i < text.length; i += 2) {
    const [row1, col1] = findPosition(matrix, text[i]);
    const [row2, col2] = findPosition(matrix, text[i + 1]);

    if (row1 === row2) {
      // Même ligne: décaler à gauche
      result += matrix[row1][mod(col1 - 1, 5)];
      result += matrix[row2][mod(col2 - 1, 5)];
    } else if (col1 === col2) {
      // Même colonne: décaler en haut
      result += matrix[mod(row1 - 1, 5)][col1];
      result += matrix[mod(row2 - 1, 5)][col2];
    } else {
      // Rectangle: échanger colonnes
      result += matrix[row1][col2];
      result += matrix[row2][col1];
    }
  }

  return result;
}

// ============================================================================
// CHIFFREMENT HILL 3×3
// ============================================================================

/**
 * Calcule le déterminant d'une matrice 3×3
 */
function det3x3(m) {
  return m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
       - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
       + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]);
}

/**
 * Calcule la matrice adjointe (cofacteurs transposés) 3×3
 */
function adjugate3x3(m) {
  const c00 =  (m[1][1] * m[2][2] - m[1][2] * m[2][1]);
  const c01 = -(m[1][0] * m[2][2] - m[1][2] * m[2][0]);
  const c02 =  (m[1][0] * m[2][1] - m[1][1] * m[2][0]);

  const c10 = -(m[0][1] * m[2][2] - m[0][2] * m[2][1]);
  const c11 =  (m[0][0] * m[2][2] - m[0][2] * m[2][0]);
  const c12 = -(m[0][0] * m[2][1] - m[0][1] * m[2][0]);

  const c20 =  (m[0][1] * m[1][2] - m[0][2] * m[1][1]);
  const c21 = -(m[0][0] * m[1][2] - m[0][2] * m[1][0]);
  const c22 =  (m[0][0] * m[1][1] - m[0][1] * m[1][0]);

  // Transposer (cofacteurs -> adjointe)
  return [
    [c00, c10, c20],
    [c01, c11, c21],
    [c02, c12, c22]
  ];
}

/**
 * Calcule l'inverse d'une matrice 3×3 modulo 26
 */
function inverseMatrix3x3Mod26(m) {
  const d = det3x3(m);
  const detMod = mod(d, 26);

  if (gcd(detMod, 26) !== 1) {
    throw new Error(`Hill: det(K)=${d} (mod 26 = ${detMod}) n'est pas premier avec 26. Matrice non inversible.`);
  }

  const detInv = modInverse(detMod, 26);
  const adj = adjugate3x3(m);

  // Inverse = (1/det) * adjugate (mod 26)
  const inv = adj.map(row =>
    row.map(val => mod(detInv * val, 26))
  );

  return inv;
}

/**
 * Multiplie une matrice 3×3 par un vecteur colonne mod 26
 */
function matrixVectorMult3(matrix, vector) {
  const result = [];
  for (let i = 0; i < 3; i++) {
    let sum = 0;
    for (let j = 0; j < 3; j++) {
      sum += matrix[i][j] * vector[j];
    }
    result.push(mod(sum, 26));
  }
  return result;
}

/**
 * Convertit un bloc de 3 lettres en vecteur numérique (A=0...Z=25)
 */
function textToVector(text) {
  return text.split('').map(ch => {
    const code = ch.toUpperCase().charCodeAt(0) - 65;
    return (code >= 0 && code < 26) ? code : 0;
  });
}

/**
 * Convertit un vecteur en texte
 */
function vectorToText(vector) {
  return vector.map(n => String.fromCharCode(mod(n, 26) + 65)).join('');
}

/**
 * Chiffre un texte avec Hill 3×3
 * @param {string} text - Texte à chiffrer (sera paddé si nécessaire)
 * @param {Array} keyMatrix - Matrice clé 3×3
 */
function hillEncrypt(text, keyMatrix) {
  text = text.toUpperCase().replace(/[^A-Z]/g, '');

  // Padding avec 'X' si longueur non multiple de 3
  while (text.length % 3 !== 0) {
    text += 'X';
  }

  let result = '';

  for (let i = 0; i < text.length; i += 3) {
    const block = text.substr(i, 3);
    const vector = textToVector(block);
    const encrypted = matrixVectorMult3(keyMatrix, vector);
    result += vectorToText(encrypted);
  }

  return result;
}

/**
 * Déchiffre un texte Hill 3×3
 */
function hillDecrypt(text, keyMatrix) {
  text = text.toUpperCase().replace(/[^A-Z]/g, '');

  const invMatrix = inverseMatrix3x3Mod26(keyMatrix);
  let result = '';

  for (let i = 0; i < text.length; i += 3) {
    const block = text.substr(i, 3);
    const vector = textToVector(block);
    const decrypted = matrixVectorMult3(invMatrix, vector);
    result += vectorToText(decrypted);
  }

  return result;
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  // Utilitaires
  gcd,
  modInverse,
  mod,

  // César
  caesarEncrypt,
  caesarDecrypt,

  // Affine
  affineEncrypt,
  affineDecrypt,

  // Playfair
  playfairEncrypt,
  playfairDecrypt,
  buildPlayfairMatrix,

  // Hill 3×3
  hillEncrypt,
  hillDecrypt,
  inverseMatrix3x3Mod26,
  det3x3
};

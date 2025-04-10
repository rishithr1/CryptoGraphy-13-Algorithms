/**
 * Cryptography Toolkit - Implementation of 15 Classical Ciphers
 * 
 * This file contains implementations of various classical cryptographic algorithms
 * including substitution ciphers, polyalphabetic ciphers, and transposition ciphers.
 */

// Utility functions
const mod = (n: number, m: number): number => ((n % m) + m) % m;

const gcd = (a: number, b: number): number => {
  if (b === 0) return a;
  return gcd(b, a % b);
};

const modInverse = (a: number, m: number): number => {
  for (let x = 1; x < m; x++) {
    if ((a * x) % m === 1) {
      return x;
    }
  }
  throw new Error(`Modular inverse does not exist for a=${a} and m=${m}`);
};

const isValidMatrix = (matrix: number[][]): boolean => {
  // Check if it's a 2x2 matrix
  if (matrix.length !== 2 || matrix[0].length !== 2 || matrix[1].length !== 2) {
    return false;
  }
  
  // Calculate determinant
  const det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26;
  
  // Check if determinant is coprime with 26
  return gcd(mod(det, 26), 26) === 1;
};

const matrixInverse = (matrix: number[][]): number[][] => {
  // Calculate determinant
  const det = mod(matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0], 26);
  
  // Calculate modular inverse of determinant
  const detInv = modInverse(det, 26);
  
  // Calculate adjugate matrix
  const adj = [
    [matrix[1][1], -matrix[0][1]],
    [-matrix[1][0], matrix[0][0]]
  ];
  
  // Calculate inverse matrix
  return [
    [mod(adj[0][0] * detInv, 26), mod(adj[0][1] * detInv, 26)],
    [mod(adj[1][0] * detInv, 26), mod(adj[1][1] * detInv, 26)]
  ];
};

// 1. Atbash Cipher
export const atbashCipher = (text: string, steps: string[] = []): string => {
  steps.push("Atbash Cipher: Replacing each letter with its reverse in the alphabet (A↔Z, B↔Y, etc.)");
  
  const result = text.split('').map(char => {
    const code = char.charCodeAt(0);
    
    // Handle uppercase letters (ASCII 65-90)
    if (code >= 65 && code <= 90) {
      const newChar = String.fromCharCode(155 - code); // 155 = 65 + 90
      steps.push(`${char} → ${newChar}`);
      return newChar;
    }
    
    // Handle lowercase letters (ASCII 97-122)
    if (code >= 97 && code <= 122) {
      const newChar = String.fromCharCode(219 - code); // 219 = 97 + 122
      steps.push(`${char} → ${newChar}`);
      return newChar;
    }
    
    // Non-alphabetic characters remain unchanged
    return char;
  }).join('');
  
  steps.push(`Final result: "${result}"`);
  return result;
};

// 2. Caesar Cipher
export const caesarCipher = (
  text: string, 
  key: number, 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  // Ensure key is within 0-25
  key = mod(key, 26);
  
  if (!encrypt) {
    key = 26 - key;
  }
  
  steps.push(`Caesar Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with shift key ${encrypt ? key : 26 - key}`);
  
  const result = text.split('').map(char => {
    const code = char.charCodeAt(0);
    
    // Handle uppercase letters (ASCII 65-90)
    if (code >= 65 && code <= 90) {
      const shifted = mod(code - 65 + key, 26) + 65;
      const newChar = String.fromCharCode(shifted);
      steps.push(`${char} → ${newChar} (${code - 65} ${encrypt ? '+' : '-'} ${encrypt ? key : 26 - key} mod 26 = ${mod(code - 65 + key, 26)})`);
      return newChar;
    }
    
    // Handle lowercase letters (ASCII 97-122)
    if (code >= 97 && code <= 122) {
      const shifted = mod(code - 97 + key, 26) + 97;
      const newChar = String.fromCharCode(shifted);
      steps.push(`${char} → ${newChar} (${code - 97} ${encrypt ? '+' : '-'} ${encrypt ? key : 26 - key} mod 26 = ${mod(code - 97 + key, 26)})`);
      return newChar;
    }
    
    // Non-alphabetic characters remain unchanged
    return char;
  }).join('');
  
  steps.push(`Final result: "${result}"`);
  return result;
};

// 3. Affine Cipher
export const affineCipher = (
  text: string, 
  keyA: number, 
  keyB: number, 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  // Validate key A (must be coprime with 26)
  if (gcd(keyA, 26) !== 1) {
    throw new Error(`Key A (${keyA}) must be coprime with 26`);
  }
  
  // Ensure key B is within 0-25
  keyB = mod(keyB, 26);
  
  steps.push(`Affine Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with keys A=${keyA}, B=${keyB}`);
  
  // For decryption, calculate modular inverse of key A
  let aInverse = 0;
  if (!encrypt) {
    aInverse = modInverse(keyA, 26);
    steps.push(`Calculated modular inverse of ${keyA} mod 26 = ${aInverse}`);
  }
  
  const result = text.split('').map(char => {
    const code = char.charCodeAt(0);
    
    // Handle uppercase letters (ASCII 65-90)
    if (code >= 65 && code <= 90) {
      const x = code - 65;
      let y;
      
      if (encrypt) {
        // E(x) = (ax + b) mod 26
        y = mod(keyA * x + keyB, 26);
        steps.push(`${char} → ${String.fromCharCode(y + 65)} (${keyA} × ${x} + ${keyB} mod 26 = ${y})`);
      } else {
        // D(y) = a^(-1) * (y - b) mod 26
        y = mod(aInverse * mod(x - keyB, 26), 26);
        steps.push(`${char} → ${String.fromCharCode(y + 65)} (${aInverse} × (${x} - ${keyB}) mod 26 = ${y})`);
      }
      
      return String.fromCharCode(y + 65);
    }
    
    // Handle lowercase letters (ASCII 97-122)
    if (code >= 97 && code <= 122) {
      const x = code - 97;
      let y;
      
      if (encrypt) {
        // E(x) = (ax + b) mod 26
        y = mod(keyA * x + keyB, 26);
        steps.push(`${char} → ${String.fromCharCode(y + 97)} (${keyA} × ${x} + ${keyB} mod 26 = ${y})`);
      } else {
        // D(y) = a^(-1) * (y - b) mod 26
        y = mod(aInverse * mod(x - keyB, 26), 26);
        steps.push(`${char} → ${String.fromCharCode(y + 97)} (${aInverse} × (${x} - ${keyB}) mod 26 = ${y})`);
      }
      
      return String.fromCharCode(y + 97);
    }
    
    // Non-alphabetic characters remain unchanged
    return char;
  }).join('');
  
  steps.push(`Final result: "${result}"`);
  return result;
};

// 4. Vigenère Cipher
export const vigenereCipher = (
  text: string, 
  key: string, 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  if (!key || key.length === 0) {
    throw new Error("Key cannot be empty");
  }
  
  // Convert key to uppercase and filter out non-alphabetic characters
  const processedKey = key.toUpperCase().replace(/[^A-Z]/g, '');
  
  if (processedKey.length === 0) {
    throw new Error("Key must contain at least one letter");
  }
  
  steps.push(`Vigenère Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with key "${processedKey}"`);
  
  let keyIndex = 0;
  const result = text.split('').map(char => {
    const code = char.charCodeAt(0);
    
    // Handle uppercase letters (ASCII 65-90)
    if (code >= 65 && code <= 90) {
      const keyChar = processedKey[keyIndex % processedKey.length];
      const keyShift = keyChar.charCodeAt(0) - 65;
      
      let shifted;
      if (encrypt) {
        // E(x) = (x + key[i]) mod 26
        shifted = mod(code - 65 + keyShift, 26) + 65;
        steps.push(`${char} + ${keyChar} → ${String.fromCharCode(shifted)} (${code - 65} + ${keyShift} mod 26 = ${mod(code - 65 + keyShift, 26)})`);
      } else {
        // D(x) = (x - key[i]) mod 26
        shifted = mod(code - 65 - keyShift, 26) + 65;
        steps.push(`${char} - ${keyChar} → ${String.fromCharCode(shifted)} (${code - 65} - ${keyShift} mod 26 = ${mod(code - 65 - keyShift, 26)})`);
      }
      
      keyIndex++;
      return String.fromCharCode(shifted);
    }
    
    // Handle lowercase letters (ASCII 97-122)
    if (code >= 97 && code <= 122) {
      const keyChar = processedKey[keyIndex % processedKey.length];
      const keyShift = keyChar.charCodeAt(0) - 65;
      
      let shifted;
      if (encrypt) {
        // E(x) = (x + key[i]) mod 26
        shifted = mod(code - 97 + keyShift, 26) + 97;
        steps.push(`${char} + ${keyChar} → ${String.fromCharCode(shifted)} (${code - 97} + ${keyShift} mod 26 = ${mod(code - 97 + keyShift, 26)})`);
      } else {
        // D(x) = (x - key[i]) mod 26
        shifted = mod(code - 97 - keyShift, 26) + 97;
        steps.push(`${char} - ${keyChar} → ${String.fromCharCode(shifted)} (${code - 97} - ${keyShift} mod 26 = ${mod(code - 97 - keyShift, 26)})`);
      }
      
      keyIndex++;
      return String.fromCharCode(shifted);
    }
    
    // Non-alphabetic characters remain unchanged
    return char;
  }).join('');
  
  steps.push(`Final result: "${result}"`);
  return result;
};

// 5. Gronsfeld Cipher
export const gronsfeldCipher = (
  text: string, 
  key: string, 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  if (!key || key.length === 0) {
    throw new Error("Key cannot be empty");
  }
  
  // Filter out non-numeric characters
  const processedKey = key.replace(/[^0-9]/g, '');
  
  if (processedKey.length === 0) {
    throw new Error("Key must contain at least one digit");
  }
  
  steps.push(`Gronsfeld Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with key "${processedKey}"`);
  
  let keyIndex = 0;
  const result = text.split('').map(char => {
    const code = char.charCodeAt(0);
    
    // Handle uppercase letters (ASCII 65-90)
    if (code >= 65 && code <= 90) {
      const keyShift = parseInt(processedKey[keyIndex % processedKey.length], 10);
      
      let shifted;
      if (encrypt) {
        // E(x) = (x + key[i]) mod 26
        shifted = mod(code - 65 + keyShift, 26) + 65;
        steps.push(`${char} + ${keyShift} → ${String.fromCharCode(shifted)} (${code - 65} + ${keyShift} mod 26 = ${mod(code - 65 + keyShift, 26)})`);
      } else {
        // D(x) = (x - key[i]) mod 26
        shifted = mod(code - 65 - keyShift, 26) + 65;
        steps.push(`${char} - ${keyShift} → ${String.fromCharCode(shifted)} (${code - 65} - ${keyShift} mod 26 = ${mod(code - 65 - keyShift, 26)})`);
      }
      
      keyIndex++;
      return String.fromCharCode(shifted);
    }
    
    // Handle lowercase letters (ASCII 97-122)
    if (code >= 97 && code <= 122) {
      const keyShift = parseInt(processedKey[keyIndex % processedKey.length], 10);
      
      let shifted;
      if (encrypt) {
        // E(x) = (x + key[i]) mod 26
        shifted = mod(code - 97 + keyShift, 26) + 97;
        steps.push(`${char} + ${keyShift} → ${String.fromCharCode(shifted)} (${code - 97} + ${keyShift} mod 26 = ${mod(code - 97 + keyShift, 26)})`);
      } else {
        // D(x) = (x - key[i]) mod 26
        shifted = mod(code - 97 - keyShift, 26) + 97;
        steps.push(`${char} - ${keyShift} → ${String.fromCharCode(shifted)} (${code - 97} - ${keyShift} mod 26 = ${mod(code - 97 - keyShift, 26)})`);
      }
      
      keyIndex++;
      return String.fromCharCode(shifted);
    }
    
    // Non-alphabetic characters remain unchanged
    return char;
  }).join('');
  
  steps.push(`Final result: "${result}"`);
  return result;
};

// 6. Beaufort Cipher
export const beaufortCipher = (
  text: string, 
  key: string, 
  steps: string[] = []
): string => {
  if (!key || key.length === 0) {
    throw new Error("Key cannot be empty");
  }
  
  // Convert key to uppercase and filter out non-alphabetic characters
  const processedKey = key.toUpperCase().replace(/[^A-Z]/g, '');
  
  if (processedKey.length === 0) {
    throw new Error("Key must contain at least one letter");
  }
  
  steps.push(`Beaufort Cipher: Processing with key "${processedKey}" (encryption and decryption are identical)`);
  
  let keyIndex = 0;
  const result = text.split('').map(char => {
    const code = char.charCodeAt(0);
    
    // Handle uppercase letters (ASCII 65-90)
    if (code >= 65 && code <= 90) {
      const keyChar = processedKey[keyIndex % processedKey.length];
      const keyCode = keyChar.charCodeAt(0);
      
      // E(x) = (key[i] - x) mod 26
      const shifted = mod(keyCode - code, 26) + 65;
      steps.push(`${keyChar} - ${char} → ${String.fromCharCode(shifted)} (${keyCode - 65} - ${code - 65} mod 26 = ${mod(keyCode - code, 26)})`);
      
      keyIndex++;
      return String.fromCharCode(shifted);
    }
    
    // Handle lowercase letters (ASCII 97-122)
    if (code >= 97 && code <= 122) {
      const keyChar = processedKey[keyIndex % processedKey.length];
      const keyCode = keyChar.charCodeAt(0);
      
      // E(x) = (key[i] - x) mod 26, adjusting for lowercase
      const shifted = mod(keyCode - 65 - (code - 97), 26) + 97;
      steps.push(`${keyChar} - ${char} → ${String.fromCharCode(shifted)} (${keyCode - 65} - ${code - 97} mod 26 = ${mod(keyCode - 65 - (code - 97), 26)})`);
      
      keyIndex++;
      return String.fromCharCode(shifted);
    }
    
    // Non-alphabetic characters remain unchanged
    return char;
  }).join('');
  
  steps.push(`Final result: "${result}"`);
  return result;
};

// 7. Auto Key Cipher
export const autoKeyCipher = (
  text: string, 
  key: string, 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  if (!key || key.length === 0) {
    throw new Error("Key cannot be empty");
  }
  
  // Convert key to uppercase and filter out non-alphabetic characters
  const processedKey = key.toUpperCase().replace(/[^A-Z]/g, '');
  
  if (processedKey.length === 0) {
    throw new Error("Key must contain at least one letter");
  }
  
  steps.push(`Auto Key Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with initial key "${processedKey}"`);
  
  // For encryption, we'll use the key followed by the plaintext
  // For decryption, we'll build the key as we go
  let fullKey = processedKey;
  let result = '';
  
  if (encrypt) {
    steps.push("Encryption: Using key + plaintext as the running key");
    
    // Process each character
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      const code = char.charCodeAt(0);
      
      // Handle uppercase letters (ASCII 65-90)
      if (code >= 65 && code <= 90) {
        const keyChar = i < fullKey.length ? fullKey[i] : fullKey[fullKey.length - 1];
        const keyShift = keyChar.charCodeAt(0) - 65;
        
        // E(x) = (x + key[i]) mod 26
        const shifted = mod(code - 65 + keyShift, 26) + 65;
        const encryptedChar = String.fromCharCode(shifted);
        
        steps.push(`${char} + ${keyChar} → ${encryptedChar} (${code - 65} + ${keyShift} mod 26 = ${mod(code - 65 + keyShift, 26)})`);
        
        result += encryptedChar;
        fullKey += char; // Add plaintext character to the key
      }
      // Handle lowercase letters (ASCII 97-122)
      else if (code >= 97 && code <= 122) {
        const keyChar = i < fullKey.length ? fullKey[i] : fullKey[fullKey.length - 1];
        const keyShift = keyChar.charCodeAt(0) - 65;
        
        // E(x) = (x + key[i]) mod 26
        const shifted = mod(code - 97 + keyShift, 26) + 97;
        const encryptedChar = String.fromCharCode(shifted);
        
        steps.push(`${char} + ${keyChar} → ${encryptedChar} (${code - 97} + ${keyShift} mod 26 = ${mod(code - 97 + keyShift, 26)})`);
        
        result += encryptedChar;
        fullKey += char.toUpperCase(); // Add uppercase plaintext character to the key
      }
      // Non-alphabetic characters remain unchanged
      else {
        result += char;
      }
    }
  } else {
    steps.push("Decryption: Building the key as we decrypt");
    
    // Process each character
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      const code = char.charCodeAt(0);
      
      // Handle uppercase letters (ASCII 65-90)
      if (code >= 65 && code <= 90) {
        const keyChar = i < fullKey.length ? fullKey[i] : fullKey[fullKey.length - 1];
        const keyShift = keyChar.charCodeAt(0) - 65;
        
        // D(x) = (x - key[i]) mod 26
        const shifted = mod(code - 65 - keyShift, 26) + 65;
        const decryptedChar = String.fromCharCode(shifted);
        
        steps.push(`${char} - ${keyChar} → ${decryptedChar} (${code - 65} - ${keyShift} mod 26 = ${mod(code - 65 - keyShift, 26)})`);
        
        result += decryptedChar;
        fullKey += decryptedChar; // Add decrypted character to the key
      }
      // Handle lowercase letters (ASCII 97-122)
      else if (code >= 97 && code <= 122) {
        const keyChar = i < fullKey.length ? fullKey[i] : fullKey[fullKey.length - 1];
        const keyShift = keyChar.charCodeAt(0) - 65;
        
        // D(x) = (x - key[i]) mod 26
        const shifted = mod(code - 97 - keyShift, 26) + 97;
        const decryptedChar = String.fromCharCode(shifted);
        
        steps.push(`${char} - ${keyChar} → ${decryptedChar} (${code - 97} - ${keyShift} mod 26 = ${mod(code - 97 - keyShift, 26)})`);
        
        result += decryptedChar;
        fullKey += decryptedChar.toUpperCase(); // Add uppercase decrypted character to the key
      }
      // Non-alphabetic characters remain unchanged
      else {
        result += char;
      }
    }
  }
  
  steps.push(`Final result: "${result}"`);
  return result;
};

// 8. Running Key Cipher
export const runningKeyCipher = (
  text: string, 
  key: string, 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  if (!key || key.length === 0) {
    throw new Error("Key cannot be empty");
  }
  
  // Convert key to uppercase and filter out non-alphabetic characters
  const processedKey = key.toUpperCase().replace(/[^A-Z]/g, '');
  
  if (processedKey.length === 0) {
    throw new Error("Key must contain at least one letter");
  }
  
  steps.push(`Running Key Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with key "${processedKey}"`);
  
  // If key is shorter than text, repeat it
  let fullKey = '';
  while (fullKey.length < text.replace(/[^A-Za-z]/g, '').length) {
    fullKey += processedKey;
  }
  
  let keyIndex = 0;
  const result = text.split('').map(char => {
    const code = char.charCodeAt(0);
    
    // Handle uppercase letters (ASCII 65-90)
    if (code >= 65 && code <= 90) {
      const keyChar = fullKey[keyIndex];
      const keyShift = keyChar.charCodeAt(0) - 65;
      
      let shifted;
      if (encrypt) {
        // E(x) = (x + key[i]) mod 26
        shifted = mod(code - 65 + keyShift, 26) + 65;
        steps.push(`${char} + ${keyChar} → ${String.fromCharCode(shifted)} (${code - 65} + ${keyShift} mod 26 = ${mod(code - 65 + keyShift, 26)})`);
      } else {
        // D(x) = (x - key[i]) mod 26
        shifted = mod(code - 65 - keyShift, 26) + 65;
        steps.push(`${char} - ${keyChar} → ${String.fromCharCode(shifted)} (${code - 65} - ${keyShift} mod 26 = ${mod(code - 65 - keyShift, 26)})`);
      }
      
      keyIndex++;
      return String.fromCharCode(shifted);
    }
    
    // Handle lowercase letters (ASCII 97-122)
    if (code >= 97 && code <= 122) {
      const keyChar = fullKey[keyIndex];
      const keyShift = keyChar.charCodeAt(0) - 65;
      
      let shifted;
      if (encrypt) {
        // E(x) = (x + key[i]) mod 26
        shifted = mod(code - 97 + keyShift, 26) + 97;
        steps.push(`${char} + ${keyChar} → ${String.fromCharCode(shifted)} (${code - 97} + ${keyShift} mod 26 = ${mod(code - 97 + keyShift, 26)})`);
      } else {
        // D(x) = (x - key[i]) mod 26
        shifted = mod(code - 97 - keyShift, 26) + 97;
        steps.push(`${char} - ${keyChar} → ${String.fromCharCode(shifted)} (${code - 97} - ${keyShift} mod 26 = ${mod(code - 97 - keyShift, 26)})`);
      }
      
      keyIndex++;
      return String.fromCharCode(shifted);
    }
    
    // Non-alphabetic characters remain unchanged
    return char;
  }).join('');
  
  steps.push(`Final result: "${result}"`);
  return result;
};

// 9. Hill Cipher
export const hillCipher = (
  text: string, 
  keyMatrix: number[][], 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  // Validate key matrix
  if (!isValidMatrix(keyMatrix)) {
    throw new Error("Invalid key matrix. Determinant must be coprime with 26.");
  }
  
  steps.push(`Hill Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with key matrix [[${keyMatrix[0][0]},${keyMatrix[0][1]}],[${keyMatrix[1][0]},${keyMatrix[1][1]}]]`);
  
  // For decryption, calculate inverse matrix
  const matrix = encrypt ? keyMatrix : matrixInverse(keyMatrix);
  
  if (!encrypt) {
    steps.push(`Calculated inverse matrix: [[${matrix[0][0]},${matrix[0][1]}],[${matrix[1][0]},${matrix[1][1]}]]`);
  }
  
  // Filter out non-alphabetic characters and convert to uppercase
  const processedText = text.toUpperCase().replace(/[^A-Z]/g, '');
  
  // Pad with 'X' if length is odd (for 2x2 matrix)
  const paddedText = processedText.length % 2 === 0 ? processedText : processedText + 'X';
  
  steps.push(`Processed text: "${paddedText}"`);
  
  let result = '';
  
  // Process text in blocks of 2 characters
  for (let i = 0; i < paddedText.length; i += 2) {
    const char1 = paddedText[i];
    const char2 = paddedText[i + 1];
    
    const x1 = char1.charCodeAt(0) - 65;
    const x2 = char2.charCodeAt(0) - 65;
    
    // Matrix multiplication
    const y1 = mod(matrix[0][0] * x1 + matrix[0][1] * x2, 26);
    const y2 = mod(matrix[1][0] * x1 + matrix[1][1] * x2, 26);
    
    const resultChar1 = String.fromCharCode(y1 + 65);
    const resultChar2 = String.fromCharCode(y2 + 65);
    
    steps.push(`[${char1},${char2}] → [${resultChar1},${resultChar2}] (Matrix multiplication)`);
    
    result += resultChar1 + resultChar2;
  }
  
  // Convert result back to match original case pattern
  let finalResult = '';
  let resultIndex = 0;
  
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const code = char.charCodeAt(0);
    
    // Handle uppercase letters (ASCII 65-90)
    if (code >= 65 && code <= 90) {
      if (resultIndex < result.length) {
        finalResult += result[resultIndex++];
      }
    }
    // Handle lowercase letters (ASCII 97-122)
    else if (code >= 97 && code <= 122) {
      if (resultIndex < result.length) {
        finalResult += result[resultIndex++].toLowerCase();
      }
    }
    // Non-alphabetic characters remain unchanged
    else {
      finalResult += char;
    }
  }
  
  steps.push(`Final result: "${finalResult}"`);
  return finalResult;
};

// 10. Rail Fence Cipher
export const railFenceCipher = (
  text: string, 
  rails: number, 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  if (rails < 2) {
    throw new Error("Number of rails must be at least 2");
  }
  
  steps.push(`Rail Fence Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with ${rails} rails`);
  
  if (encrypt) {
    // Create the rail fence pattern
    const fence: string[][] = Array(rails).fill('').map(() => []);
    
    let rail = 0;
    let direction = 1; // 1 for down, -1 for up
    
    // Place characters in the fence
    for (let i = 0; i < text.length; i++) {
      fence[rail].push(text[i]);
      
      // Change direction if we hit the top or bottom rail
      if (rail === 0) {
        direction = 1;
      } else if (rail === rails - 1) {
        direction = -1;
      }
      
      rail += direction;
    }
    
    // Visualize the rail fence
    const visualization = Array(rails).fill('').map(() => Array(text.length).fill(' '));
    
    rail = 0;
    direction = 1;
    
    for (let i = 0; i < text.length; i++) {
      visualization[rail][i] = text[i];
      
      if (rail === 0) {
        direction = 1;
      } else if (rail === rails - 1) {
        direction = -1;
      }
      
      rail += direction;
    }
    
    // Add visualization to steps
    steps.push("Rail fence pattern:");
    for (let i = 0; i < rails; i++) {
      steps.push(visualization[i].join(''));
    }
    
    // Read off the fence
    const result = fence.flat().join('');
    steps.push(`Final result: "${result}"`);
    return result;
  } else {
    // Decryption
    // Create the rail fence pattern with placeholders
    const fence: string[][] = Array(rails).fill('').map(() => []);
    
    let rail = 0;
    let direction = 1; // 1 for down, -1 for up
    
    // Mark positions in the fence
    for (let i = 0; i < text.length; i++) {
      fence[rail].push('*');
      
      // Change direction if we hit the top or bottom rail
      if (rail === 0) {
        direction = 1;
      } else if (rail === rails - 1) {
        direction = -1;
      }
      
      rail += direction;
    }
    
    // Fill the fence with the ciphertext
    let index = 0;
    for (let i = 0; i < rails; i++) {
      for (let j = 0; j < fence[i].length; j++) {
        fence[i][j] = text[index++];
      }
    }
    
    // Visualize the filled fence
    steps.push("Filled rail fence pattern:");
    for (let i = 0; i < rails; i++) {
      steps.push(fence[i].join(' '));
    }
    
    // Read off the fence in zigzag pattern
    let result = '';
    rail = 0;
    direction = 1;
    
    for (let i = 0; i < text.length; i++) {
      result += fence[rail].shift() || '';
      
      // Change direction if we hit the top or bottom rail
      if (rail === 0) {
        direction = 1;
      } else if (rail === rails - 1) {
        direction = -1;
      }
      
      rail += direction;
    }
    
    steps.push(`Final result: "${result}"`);
    return result;
  }
};

// 11. Route Cipher
export const routeCipher = (
  text: string, 
  rows: number, 
  cols: number, 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  if (rows < 2 || cols < 2) {
    throw new Error("Number of rows and columns must be at least 2");
  }
  
  steps.push(`Route Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with ${rows}×${cols} grid using spiral route`);
  
  if (encrypt) {
    // Create a grid and fill it with the text
    const grid: string[][] = Array(rows).fill('').map(() => Array(cols).fill(' '));
    
    // Fill the grid row by row
    let index = 0;
    for (let i = 0; i < rows; i++) {
      for (let j = 0; j < cols; j++) {
        if (index < text.length) {
          grid[i][j] = text[index++];
        }
      }
    }
    
    // Visualize the grid
    steps.push("Grid arrangement:");
    for (let i = 0; i < rows; i++) {
      steps.push(grid[i].join(' '));
    }
    
    // Read the grid in a spiral pattern
    let result = '';
    let topRow = 0;
    let bottomRow = rows - 1;
    let leftCol = 0;
    let rightCol = cols - 1;
    
    while (topRow <= bottomRow && leftCol <= rightCol) {
      // Read top row
      for (let j = leftCol; j <= rightCol; j++) {
        result += grid[topRow][j];
      }
      topRow++;
      
      // Read right column
      for (let i = topRow; i <= bottomRow; i++) {
        result += grid[i][rightCol];
      }
      rightCol--;
      
      // Read bottom row
      if (topRow <= bottomRow) {
        for (let j = rightCol; j >= leftCol; j--) {
          result += grid[bottomRow][j];
        }
        bottomRow--;
      }
      
      // Read left column
      if (leftCol <= rightCol) {
        for (let i = bottomRow; i >= topRow; i--) {
          result += grid[i][leftCol];
        }
        leftCol++;
      }
    }
    
    steps.push(`Final result: "${result}"`);
    return result;
  } else {
    // Decryption
    // Create an empty grid
    const grid: string[][] = Array(rows).fill('').map(() => Array(cols).fill(' '));
    
    // Fill the grid in a spiral pattern
    let index = 0;
    let topRow = 0;
    let bottomRow = rows - 1;
    let leftCol = 0;
    let rightCol = cols - 1;
    
    while (topRow <= bottomRow && leftCol <= rightCol && index < text.length) {
      // Fill top row
      for (let j = leftCol; j <= rightCol && index < text.length; j++) {
        grid[topRow][j] = text[index++];
      }
      topRow++;
      
      // Fill right column
      for (let i = topRow; i <= bottomRow && index < text.length; i++) {
        grid[i][rightCol] = text[index++];
      }
      rightCol--;
      
      // Fill bottom row
      if (topRow <= bottomRow) {
        for (let j = rightCol; j >= leftCol && index < text.length; j--) {
          grid[bottomRow][j] = text[index++];
        }
        bottomRow--;
      }
      
      // Fill left column
      if (leftCol <= rightCol) {
        for (let i = bottomRow; i >= topRow && index < text.length; i--) {
          grid[i][leftCol] = text[index++];
        }
        leftCol++;
      }
    }
    
    // Visualize the filled grid
    steps.push("Filled grid:");
    for (let i = 0; i < rows; i++) {
      steps.push(grid[i].join(' '));
    }
    
    // Read the grid row by row
    let result = '';
    for (let i = 0; i < rows; i++) {
      for (let j = 0; j < cols; j++) {
        if (grid[i][j] !== ' ') {
          result += grid[i][j];
        }
      }
    }
    
    steps.push(`Final result: "${result}"`);
    return result;
  }
};

// 12. Columnar Cipher
export const columnarCipher = (
  text: string, 
  key: string, 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  if (!key || key.length === 0) {
    throw new Error("Key cannot be empty");
  }
  
  // Ensure key contains only digits
  if (!/^\d+$/.test(key)) {
    throw new Error("Key must contain only digits");
  }
  
  steps.push(`Columnar Transposition Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with key "${key}"`);
  
  // Convert key to column order
  const keyOrder: number[] = [];
  for (let i = 0; i < key.length; i++) {
    keyOrder.push(parseInt(key[i], 10));
  }
  
  if (encrypt) {
    // Calculate number of rows needed
    const numRows = Math.ceil(text.length / key.length);
    
    // Create the grid and fill it with the text
    const grid: string[][] = Array(numRows).fill('').map(() => Array(key.length).fill(' '));
    
    let index = 0;
    for (let i = 0; i < numRows; i++) {
      for (let j = 0; j < key.length; j++) {
        if (index < text.length) {
          grid[i][j] = text[index++];
        }
      }
    }
    
    // Visualize the grid
    steps.push("Grid arrangement:");
    steps.push(`Key: ${keyOrder.join(' ')}`);
    for (let i = 0; i < numRows; i++) {
      steps.push(grid[i].join(' '));
    }
    
    // Read columns according to key order
    let result = '';
    for (let keyDigit = 1; keyDigit <= Math.max(...keyOrder); keyDigit++) {
      for (let j = 0; j < key.length; j++) {
        if (keyOrder[j] === keyDigit) {
          for (let i = 0; i < numRows; i++) {
            if (grid[i][j] !== ' ') {
              result += grid[i][j];
            }
          }
        }
      }
    }
    
    steps.push(`Final result: "${result}"`);
    return result;
  } else {
    // Decryption
    // Calculate number of rows needed
    const numRows = Math.ceil(text.length / key.length);
    const lastRowLength = text.length % key.length || key.length;
    
    // Create the grid
    const grid: string[][] = Array(numRows).fill('').map(() => Array(key.length).fill(' '));
    
    // Calculate column lengths
    const colLengths: number[] = Array(key.length).fill(numRows);
    if (text.length % key.length !== 0) {
      for (let j = 0; j < key.length; j++) {
        if (keyOrder[j] > lastRowLength) {
          colLengths[j]--;
        }
      }
    }
    
    // Fill the grid column by column according to key order
    let index = 0;
    for (let keyDigit = 1; keyDigit <= Math.max(...keyOrder); keyDigit++) {
      for (let j = 0; j < key.length; j++) {
        if (keyOrder[j] === keyDigit) {
          for (let i = 0; i < colLengths[j]; i++) {
            if (index < text.length) {
              grid[i][j] = text[index++];
            }
          }
        }
      }
    }
    
    // Visualize the filled grid
    steps.push("Filled grid:");
    steps.push(`Key: ${keyOrder.join(' ')}`);
    for (let i = 0; i < numRows; i++) {
      steps.push(grid[i].join(' '));
    }
    
    // Read the grid row by row
    let result = '';
    for (let i = 0; i < numRows; i++) {
      for (let j = 0; j < key.length; j++) {
        if (grid[i][j] !== ' ') {
          result += grid[i][j];
        }
      }
    }
    
    steps.push(`Final result: "${result}"`);
    return result;
  }
};

// 13. Double Transposition Cipher
export const doubleTranspositionCipher = (
  text: string, 
  key1: string, 
  key2: string, 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  if (!key1 || key1.length === 0 || !key2 || key2.length === 0) {
    throw new Error("Both keys cannot be empty");
  }
  
  // Ensure keys contain only digits
  if (!/^\d+$/.test(key1) || !/^\d+$/.test(key2)) {
    throw new Error("Keys must contain only digits");
  }
  
  steps.push(`Double Transposition Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with keys "${key1}" and "${key2}"`);
  
  if (encrypt) {
    // First columnar transposition
    steps.push("First transposition:");
    const firstResult = columnarCipher(text, key1, true, steps);
    
    // Second columnar transposition
    steps.push("Second transposition:");
    const finalResult = columnarCipher(firstResult, key2, true, steps);
    
    steps.push(`Final result: "${finalResult}"`);
    return finalResult;
  } else {
    // First columnar transposition (reverse of second encryption step)
    steps.push("First transposition (reverse of second encryption):");
    const firstResult = columnarCipher(text, key2, false, steps);
    
    // Second columnar transposition (reverse of first encryption step)
    steps.push("Second transposition (reverse of first encryption):");
    const finalResult = columnarCipher(firstResult, key1, false, steps);
    
    steps.push(`Final result: "${finalResult}"`);
    return finalResult;
  }
};

// 14. Myszkowski Cipher
export const myszkowskiCipher = (
  text: string, 
  key: string, 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  if (!key || key.length === 0) {
    throw new Error("Key cannot be empty");
  }
  
  // Convert key to uppercase and filter out non-alphabetic characters
  const processedKey = key.toUpperCase().replace(/[^A-Z]/g, '');
  
  if (processedKey.length === 0) {
    throw new Error("Key must contain at least one letter");
  }
  
  steps.push(`Myszkowski Transposition Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with key "${processedKey}"`);
  
  if (encrypt) {
    // Find unique characters in the key and assign numeric values
    const uniqueChars = [...new Set(processedKey)].sort();
    const keyValues: number[] = [];
    
    for (let i = 0; i < processedKey.length; i++) {
      keyValues.push(uniqueChars.indexOf(processedKey[i]) + 1);
    }
    
    // Calculate number of rows needed
    const numRows = Math.ceil(text.length / processedKey.length);
    
    // Create the grid and fill it with the text
    const grid: string[][] = Array(numRows).fill('').map(() => Array(processedKey.length).fill(' '));
    
    let index = 0;
    for (let i = 0; i < numRows; i++) {
      for (let j = 0; j < processedKey.length; j++) {
        if (index < text.length) {
          grid[i][j] = text[index++];
        }
      }
    }
    
    // Visualize the grid
    steps.push("Grid arrangement:");
    steps.push(`Key: ${processedKey.split('').join(' ')}`);
    steps.push(`Numeric values: ${keyValues.join(' ')}`);
    for (let i = 0; i < numRows; i++) {
      steps.push(grid[i].join(' '));
    }
    
    // Read columns according to key values, handling duplicates
    let result = '';
    for (let keyValue = 1; keyValue <= uniqueChars.length; keyValue++) {
      // Find all columns with the current key value
      const columns = [];
      for (let j = 0; j < processedKey.length; j++) {
        if (keyValues[j] === keyValue) {
          columns.push(j);
        }
      }
      
      // Read these columns row by row (for duplicates)
      for (let i = 0; i < numRows; i++) {
        for (const col of columns) {
          if (grid[i][col] !== ' ') {
            result += grid[i][col];
          }
        }
      }
    }
    
    steps.push(`Final result: "${result}"`);
    return result;
  } else {
    // Decryption is more complex for Myszkowski
    // Find unique characters in the key and assign numeric values
    const uniqueChars = [...new Set(processedKey)].sort();
    const keyValues: number[] = [];
    
    for (let i = 0; i < processedKey.length; i++) {
      keyValues.push(uniqueChars.indexOf(processedKey[i]) + 1);
    }
    
    // Calculate number of rows needed
    const numRows = Math.ceil(text.length / processedKey.length);
    
    // Create the grid
    const grid: string[][] = Array(numRows).fill('').map(() => Array(processedKey.length).fill(' '));
    
    // Calculate column lengths and positions
    let index = 0;
    for (let keyValue = 1; keyValue <= uniqueChars.length; keyValue++) {
      // Find all columns with the current key value
      const columns = [];
      for (let j = 0; j < processedKey.length; j++) {
        if (keyValues[j] === keyValue) {
          columns.push(j);
        }
      }
      
      // Fill these columns row by row (for duplicates)
      for (let i = 0; i < numRows && index < text.length; i++) {
        for (const col of columns) {
          if (i < numRows && index < text.length) {
            grid[i][col] = text[index++];
          }
        }
      }
    }
    
    // Visualize the filled grid
    steps.push("Filled grid:");
    steps.push(`Key: ${processedKey.split('').join(' ')}`);
    steps.push(`Numeric values: ${keyValues.join(' ')}`);
    for (let i = 0; i < numRows; i++) {
      steps.push(grid[i].join(' '));
    }
    
    // Read the grid row by row
    let result = '';
    for (let i = 0; i < numRows; i++) {
      for (let j = 0; j < processedKey.length; j++) {
        if (grid[i][j] !== ' ') {
          result += grid[i][j];
        }
      }
    }
    
    steps.push(`Final result: "${result}"`);
    return result;
  }
};

// 15. Grilles Cipher
export const grillesCipher = (
  text: string, 
  mask: string, 
  encrypt: boolean = true, 
  steps: string[] = []
): string => {
  // Parse the mask into a 2D array
  const maskRows = mask.trim().split('\n');
  const rows = maskRows.length;
  const cols = maskRows[0].length;
  
  // Validate mask dimensions
  for (const row of maskRows) {
    if (row.length !== cols) {
      throw new Error("Mask must be a rectangular grid");
    }
  }
  
  // Convert mask to a 2D array of booleans (true for holes, false for solid)
  const grille: boolean[][] = [];
  for (const row of maskRows) {
    const grilleRow: boolean[] = [];
    for (const cell of row) {
      grilleRow.push(cell === '1');
    }
    grille.push(grilleRow);
  }
  
  steps.push(`Grilles Cipher: ${encrypt ? 'Encrypting' : 'Decrypting'} with ${rows}×${cols} grille`);
  steps.push("Grille pattern (1 = hole, 0 = solid):");
  for (const row of maskRows) {
    steps.push(row);
  }
  
  if (encrypt) {
    // Count the number of holes in the grille
    let holeCount = 0;
    for (let i = 0; i < rows; i++) {
      for (let j = 0; j < cols; j++) {
        if (grille[i][j]) {
          holeCount++;
        }
      }
    }
    
    // Check if we have enough holes for the text
    if (text.length > holeCount * 4) {
      throw new Error(`Text is too long for this grille. Maximum length is ${holeCount * 4} characters.`);
    }
    
    // Create a grid to hold the ciphertext
    const grid: string[][] = Array(rows).fill('').map(() => Array(cols).fill(' '));
    
    let textIndex = 0;
    
    // Place characters through the grille in 4 rotations
    for (let rotation = 0; rotation < 4 && textIndex < text.length; rotation++) {
      steps.push(`Rotation ${rotation * 90}°:`);
      
      // Place characters through the holes
      for (let i = 0; i < rows && textIndex < text.length; i++) {
        for (let j = 0; j < cols && textIndex < text.length; j++) {
          if (grille[i][j]) {
            grid[i][j] = text[textIndex++];
          }
        }
      }
      
      // Visualize current grid state
      const gridState = Array(rows).fill('').map((_, i) => grid[i].join(' '));
      steps.push(gridState.join('\n'));
      
      // Rotate the grille 90 degrees clockwise
      const rotatedGrille: boolean[][] = Array(cols).fill(false).map(() => Array(rows).fill(false));
      for (let i = 0; i < rows; i++) {
        for (let j = 0; j < cols; j++) {
          rotatedGrille[j][rows - 1 - i] = grille[i][j];
        }
      }
      
      // Update grille for next rotation
      for (let i = 0; i < rows; i++) {
        for (let j = 0; j < cols; j++) {
          grille[i][j] = rotatedGrille[i][j];
        }
      }
    }
    
    // Read the grid row by row to get the ciphertext
    let result = '';
    for (let i = 0; i < rows; i++) {
      for (let j = 0; j < cols; j++) {
        if (grid[i][j] !== ' ') {
          result += grid[i][j];
        }
      }
    }
    
    steps.push(`Final result: "${result}"`);
    return result;
  } else {
    // Decryption
    // Create a grid with the ciphertext
    const grid: string[][] = Array(rows).fill('').map(() => Array(cols).fill(' '));
    
    let index = 0;
    for (let i = 0; i < rows; i++) {
      for (let j = 0; j < cols; j++) {
        if (index < text.length) {
          grid[i][j] = text[index++];
        }
      }
    }
    
    steps.push("Filled grid:");
    const gridState = Array(rows).fill('').map((_, i) => grid[i].join(' '));
    steps.push(gridState.join('\n'));
    
    // Read the text through the grille in 4 rotations
    let result = '';
    
    for (let rotation = 0; rotation < 4; rotation++) {
      steps.push(`Rotation ${rotation * 90}°:`);
      
      // Read characters through the holes
      for (let i = 0; i < rows; i++) {
        for (let j = 0; j < cols; j++) {
          if (grille[i][j] && grid[i][j] !== ' ') {
            result += grid[i][j];
            steps.push(`Reading ${grid[i][j]} at position (${i},${j})`);
          }
        }
      }
      
      // Rotate the grille 90 degrees clockwise
      const rotatedGrille: boolean[][] = Array(cols).fill(false).map(() => Array(rows).fill(false));
      for (let i = 0; i < rows; i++) {
        for (let j = 0; j < cols; j++) {
          rotatedGrille[j][rows - 1 - i] = grille[i][j];
        }
      }
      
      // Update grille for next rotation
      for (let i = 0; i < rows; i++) {
        for (let j = 0; j < cols; j++) {
          grille[i][j] = rotatedGrille[i][j];
        }
      }
    }
    
    steps.push(`Final result: "${result}"`);
    return result;
  }
};
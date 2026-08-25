// assets/auth.js
// Cifrado 100% en el navegador con la Web Crypto API nativa (sin librerías externas).
// Cada usuario se guarda como: { username, salt, iv, data }
// - salt: usado con PBKDF2 para derivar una clave AES-256 a partir de la contraseña
// - iv + data: un texto "marcador" cifrado con esa clave (AES-GCM)
// Iniciar sesión = intentar descifrar el marcador con la contraseña ingresada.
// Si el descifrado funciona (la autenticación de AES-GCM lo verifica), la contraseña es correcta.

const MARKER = "TRANSGIRAR_OK";
const PBKDF2_ITERATIONS = 200000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBase64(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}
function fromBase64(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveKey(password, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Crea una entrada cifrada nueva para un usuario. Devuelve el objeto listo para guardar en build-info.txt */
async function createUserEntry(username, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, encoder.encode(MARKER)
  );
  return {
    username: username.trim().toLowerCase(),
    salt: toBase64(salt),
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(ciphertext)),
  };
}

/** Intenta iniciar sesión: devuelve true solo si la contraseña descifra correctamente el marcador */
async function verifyLogin(entry, password) {
  try {
    const salt = fromBase64(entry.salt);
    const iv = fromBase64(entry.iv);
    const data = fromBase64(entry.data);
    const key = await deriveKey(password, salt);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return decoder.decode(plaintext) === MARKER;
  } catch (err) {
    // AES-GCM lanza un error si la clave (contraseña) es incorrecta: autenticación fallida
    return false;
  }
}

async function loadUsers() {
  const res = await fetch("./build-info.txt", { cache: "no-store" });
  if (!res.ok) return [];
  const text = await res.text();
  try {
    return JSON.parse(text || "[]");
  } catch {
    return [];
  }
}

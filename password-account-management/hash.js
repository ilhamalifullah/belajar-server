import crypto from 'crypto';
import { fileURLToPath } from 'url';
import path from 'path';


// Parameter PBKDF2
const DEFAULT_ITERATIONS = 100000; // bisa disesuaikan
const KEYLEN = 64; // panjang key (bytes)
const DIGEST = 'sha512';
const SALT_BYTES = 16; // 128-bit salt


function generateSalt(bytes = SALT_BYTES) {
  return crypto.randomBytes(bytes).toString('hex');
}


function hashPassword(password, iterations = DEFAULT_ITERATIONS) {
  if (typeof password !== 'string' || password.length === 0) throw new Error('Password harus string tidak kosong');
  const salt = generateSalt();
  const hash = crypto.pbkdf2Sync(password, Buffer.from(salt, 'hex'), iterations, KEYLEN, DIGEST);
  return `${iterations}:${salt}:${hash.toString('hex')}`; // simpan ini
}


function verifyPassword(password, stored) {
  // stored format: iterations:salt:hash
  if (!stored || typeof stored !== 'string') return false;
  const parts = stored.split(':');
  if (parts.length !== 3) return false;
  const [iterationsStr, saltHex, hashHex] = parts;
  const iterations = parseInt(iterationsStr, 10);
  if (!Number.isFinite(iterations) || iterations <= 0) return false;

  const expectedLen = Buffer.from(hashHex, 'hex').length;
  const derived = crypto.pbkdf2Sync(password, Buffer.from(saltHex, 'hex'), iterations, expectedLen, DIGEST);
  // gunakan timing-safe compare
  return crypto.timingSafeEqual(derived, Buffer.from(hashHex, 'hex'));
}


// --- CLI sederhana untuk demo dan pengujian ---
const __filename = fileURLToPath(import.meta.url);
const scriptName = path.basename(__filename);

if (process.argv[1] === __filename) {
  const argv = process.argv.slice(2);
  const cmd = argv[0];

  if (cmd === 'hash') {
	const password = argv[1];
	if (!password) {
	  console.error(`Usage: node ${scriptName} hash <password>`);
	  process.exit(1);
	}
	const stored = hashPassword(password);
	console.log('Stored string (simpan di DB):');
	console.log(stored);
	process.exit(0);
  }

  if (cmd === 'verify') {
	const password = argv[1];
	const stored = argv[2];
	if (!password || !stored) {
	  console.error(`Usage: node ${scriptName} verify <password> <stored-string>`);
	  process.exit(1);
	}
	const ok = verifyPassword(password, stored);
	console.log(ok ? 'VERIFIED ✅ (password cocok)' : 'FAILED ❌ (password tidak cocok)');
	process.exit(0);
  }

  // jika tidak ada perintah
  console.log('Simple Hashing CLI');
  console.log('Commands:');
  console.log(` node ${scriptName} hash <password> # buat hash + salt`);
  console.log(` node ${scriptName} verify <pw> <stored> # verifikasi password`);
}


export { hashPassword, verifyPassword };
// Usage: node encrypt-csv.js "your password"   (run in the folder containing 1.csv and 2.csv)
// Produces 1.csv.enc and 2.csv.enc (AES-256-GCM, PBKDF2-SHA256 250k iterations).
const fs = require("fs"), crypto = require("crypto");
const pw = process.argv[2];
if (!pw || pw.length < 8) { console.error("Give a password of 8+ characters: node encrypt-csv.js \"password\""); process.exit(1); }
for (const f of ["1.csv", "2.csv"]) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(pw, salt, 250000, 32, "sha256");
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(fs.readFileSync(f)), c.final(), c.getAuthTag()]);
  fs.writeFileSync(f + ".enc", Buffer.concat([Buffer.from("NPG1"), salt, iv, ct]));
  console.log("wrote " + f + ".enc");
}

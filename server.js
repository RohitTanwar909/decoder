const express = require("express");
const crypto = require("crypto");

const app = express();

app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;

const KEY_HEX =
  "e7109544dab612bd5b80b8a427ac474ba5541b9efff7a4ca1c8ef85df2489c23";

const KEY = Buffer.from(KEY_HEX, "hex");

function hexToBuffer(value, name) {
  if (typeof value !== "string" || !/^[0-9a-fA-F]+$/.test(value)) {
    throw new Error(`Invalid ${name}`);
  }

  return Buffer.from(value, "hex");
}

function decodeFile(file) {
  if (!file) {
    throw new Error("Missing file");
  }

  // Already decrypted
  if (!file._x) {
    return {
      encrypted: false,
      file,
      downloadLink: file.downloadLink || null,
      streamUrl: file.streamUrl || null,
      fileName: file.fileName || null,
    };
  }

  if (!file.p || !file.s || !file.h) {
    throw new Error("Encrypted file requires p, s and h");
  }

  const iv = hexToBuffer(file.s, "IV");
  const ciphertext = hexToBuffer(file.p, "ciphertext");
  const authTag = hexToBuffer(file.h, "auth tag");

  if (KEY.length !== 32) {
    throw new Error("Invalid AES-256 key");
  }

  if (iv.length !== 12) {
    throw new Error(`Invalid IV length: ${iv.length} bytes`);
  }

  if (authTag.length !== 16) {
    throw new Error(`Invalid auth tag length: ${authTag.length} bytes`);
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    KEY,
    iv,
    {
      authTagLength: 16,
    }
  );

  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  const decrypted = JSON.parse(
    plaintext.toString("utf8")
  );

  return {
    encrypted: true,
    file: decrypted,
    downloadLink: decrypted.downloadLink || null,
    streamUrl: decrypted.streamUrl || null,
    fileName: decrypted.fileName || null,
  };
}


// Health check
app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "DiskWala Decoder API",
  });
});


// Decoder
app.post("/decode", (req, res) => {
  try {
    const file = req.body?.file;

    if (!file) {
      return res.status(400).json({
        ok: false,
        error: "Missing file",
      });
    }

    const result = decodeFile(file);

    return res.json({
      ok: true,
      ...result,
    });

  } catch (error) {
    console.error("Decode error:", error);

    return res.status(400).json({
      ok: false,
      error: error.message || "Unable to decode file",
    });
  }
});


app.listen(PORT, "0.0.0.0", () => {
  console.log(`Decoder API running on port ${PORT}`);
});

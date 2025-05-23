const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const dictionaryPath = path.join(__dirname, "dictionary.txt");
let dictionary;

fs.readFile(dictionaryPath, "utf-8", (err, data) => {
  if (err) {
    console.error("Error loading dictionary:", err);
  } else {
    dictionary = data.split("\n").map((line) => line.trim().toLowerCase());
    console.log("Dictionary loaded successfully.");
  }
});

app.post("/check-password", async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ message: "Password is required" });
  }

  try {
    // Check for breach (HaveIBeenPwned API)
    const sha1Hash = crypto
      .createHash("sha1")
      .update(password)
      .digest("hex")
      .toUpperCase();
    const prefix = sha1Hash.slice(0, 5);
    const suffix = sha1Hash.slice(5);

    const hibpResponse = await axios.get(
      `https://api.pwnedpasswords.com/range/${prefix}`
    );
    const hashes = hibpResponse.data.split("\n").map((line) => line.split(":"));
    const found = hashes.find(([hashSuffix]) => hashSuffix === suffix);

    if (found) {
      return res.json({
        pwned: true,
        count: parseInt(found[1], 10),
      });
    } else {
      return res.json({ pwned: false });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.post("/check-dictionary", (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ message: "Password is required" });
  }

  if (!dictionary) {
    return res.status(500).json({ message: "Dictionary not loaded" });
  }

  // Check if the password is in the dictionary
  const isInDictionary = dictionary.includes(password.toLowerCase().trim());

  if (isInDictionary) {
    return res.json({
      isWeak: true,
      message: "To geslo je pogosto uporabljeno in se nahaja v slovarju.",
    });
  } else {
    return res.json({
      isWeak: false,
      message: "To geslo ni v slovarju, ni pogosto uporabljeno.",
    });
  }
});

app.listen(3001, () =>
  console.log("✅ Server running on http://localhost:3001")
);

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");

const app = express();
app.use(express.json());

app.post("/check-password", async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ message: "Password is required" });
  }

  try {
    const sha1Hash = crypto
      .createHash("sha1")
      .update(password)
      .digest("hex")
      .toUpperCase();
    const prefix = sha1Hash.slice(0, 5);
    const suffix = sha1Hash.slice(5);
    console.log(`Prefix: ${prefix}, Suffix: ${suffix}`);

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

app.listen(3000, () =>
  console.log("✅ Server running on http://localhost:3000")
);

const express = require("express");
const speakeasy = require("speakeasy");
const uuid = require("uuid");
const PORT = process.env.PORT || 5000;
const { JsonDB } = require("node-json-db");
const { Config } = require("node-json-db/dist/lib/JsonDBConfig");

const app = express();
app.use(express.json());

const db = new JsonDB(new Config("Node2fa-db", true, true, "/"));

//routes
app.get("/api", (req, res) => {
  res.status(200).json({ message: "Welcome To Node2FA Server Application" });
});

app.post("/api/register", (req, res) => {
  const id = uuid.v4();

  try {
    const path = `/user/${id}`;

    //gen secret key
    const tempSecret = speakeasy.generateSecret();

    db.push(path, { id, tempSecret });

    res.status(200).json({ id, secret: tempSecret.base32 });
  } catch (err) {
    if (err) {
      console.log(err);
      res.status(500).json({ error: `What Went Wrong: ${err}` });
    }
  }
});

app.post("/api/verify", (req, res) => {
  const { token, userId } = req.body;
  try {
    const path = `/user/${userId}`;
    const user = db.getData(path);

    const { base32: secret } = user.tempSecret;

    //verify token
    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
    });

    //check if verified, Do Something
    if (verified) {
      db.push(path, { id: userId, secret: user.tempSecret });
      res.status(200).json({
        verified: true,
      });
    } else {
      res.status(500).json({
        verified: false,
      });
    }
  } catch (err) {
    if (err) {
      res.status(500).json({
        message: `Something Went Wrong: ${err}`,
      });
    }
  }
});

app.listen(PORT, () => console.log("Server running on port", PORT));

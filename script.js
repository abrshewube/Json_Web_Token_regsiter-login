const express = require("express");
const app = express();
const path = require("path");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const Port = 8080;
const dotenv = require("dotenv");
const user = require("./models/Users");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
dotenv.config();

app.use("/", express.static(path.join(__dirname, "assets")));
app.use(bodyParser.json());

mongoose.connect(process.env.Mong_Url).then(() => {
  console.log("Db connected");
});

app.post("/api/change-password", async (req, res) => {
  const { token, newpassword } = req.body;
  jwt.verify(token, JWT_Secrete);
  const _id = user._id;
  const hashedPassword = await bcrypt.hash(newpassword, 10);
  await user.updateOn(
    { _id },
    {
      $set: { password: hashedPassword },
    }
  );
});
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await user.findOne({ username }).lean();

  if (!user) {
    return res.json({ status: "error", error: "Invalid username or password" });
  }
  if (await bcrypt.compare(password, user.password)) {
    const token = jwt.sign(
      { id: user._id, username: user.username },
      JWT_Secrete
    );

    return res.json({ status: "ok", data: token });
  }
  res.json({ status: "error", error: "Inavalid username or password" });
});

app.post("/api/regsiter", async (req, res) => {
  const { username, password: plainTextPassword } = req.body;

  if (!username || typeof username !== "string") {
    return res.json({ status: "error", error: "Inavalid username" });
  }
  if (!plainTextPassword || typeof plainTextPassword !== "string") {
    return res.json({ status: "error", error: "Invalid password" });
  }
  if (plainTextPassword.length < 5) {
    return res.json({ status: "error", error: "Password too small" });
  }
  const password = await bcrypt.hash(plainTextPassword);

  try {
    const response = await user.create({
      username,
      password,
    });
    console.log(response);
  } catch (error) {
    if (error.code === 11000) {
      return res.json({ status: "error", error: "User already in use" });
    }
    throw error;
  }
  res.json({ status: "ok" });
});

app.listen(Port, () => {
  console.log(`server is running on port:${Port} `);
});

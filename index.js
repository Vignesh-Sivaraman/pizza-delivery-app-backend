import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
dotenv.config();
import mongodb from "mongodb";
import { MongoClient } from "mongodb";
const URL = process.env.DB;
// let user = [];

const app = express();
// MidleWare
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:3000",
  })
);

const createConnection = async () => {
  const client = new MongoClient(URL);
  await client.connect();
  console.log("MongoDB connected");
  return client;
};
const client = await createConnection();

app.get("/", (req, res) => {
  res.json({ message: "Success" });
});

app.post("/register", async (req, res) => {
  try {
    let user = client.db("pizzaDB").collection("Registration");
    let salt = await bcrypt.genSalt(10);
    let hash = await bcrypt.hash(req.body.password, salt);
    req.body.password = hash;
    let final = await user.insertOne(req.body);
    res.json({ message: "User successfully registered" });
  } catch (err) {
    console.log(err);
    res.json(err);
  }
});

app.post("/login", async (req, res) => {
  try {
    //getting the data from the db for the sent email
    let user = await client
      .db("pizzaDB")
      .collection("Registration")
      .findOne({ email: req.body.email });
    // Login logic
    if (user) {
      let compare = await bcrypt.compare(req.body.password, user.password);
      if (compare) {
        let token = jwt.sign({ _id: user._id }, process.env.SECRET, {
          expiresIn: "20m",
        });
        res.json({ token });
        // res.json({ message: "logged in successfully" });
      } else {
        res.json({ message: "password is wrong" });
      }
    } else {
      res.status(401).json({ message: "user email not found" });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.listen(process.env.PORT || 3001, () => {
  console.log("server listening on port 3001");
});

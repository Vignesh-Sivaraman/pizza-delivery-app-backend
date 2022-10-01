import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
dotenv.config();
import { MongoClient } from "mongodb";
const URL = process.env.DB;
import nodemailer from "nodemailer";

const app = express();

// MidleWare
app.use(express.json());
//cors
app.use(
  cors({
    origin: "http://localhost:3000",
  })
);

// Establishing connection to database
const createConnection = async () => {
  const client = new MongoClient(URL);
  await client.connect();
  console.log("MongoDB connected");
  return client;
};
const client = await createConnection();

// mail verification

// nodemailer transporter module

const transporter = nodemailer.createTransport({
  host: process.env.HOST,
  service: process.env.SERVICE,
  port: Number(process.env.EMAILPORT),
  secure: Boolean(process.env.SECURE),
  auth: {
    user: process.env.USER,
    pass: process.env.PASS,
  },
});

const verifymail = async (email, subject, text) => {
  try {
    await transporter.sendMail({
      from: process.env.USER,
      to: email,
      subject: subject,
      text: text,
    });
    console.log("email sent successfully");
  } catch (error) {
    console.log(error);
  }
};

app.get("/", (req, res) => {
  res.json({ message: "Success" });
});

// app.post("/register", async (req, res) => {
//   try {
//     let user = client.db("pizzaDB").collection("Registration");
//     let salt = await bcrypt.genSalt(10);
//     let hash = await bcrypt.hash(req.body.password, salt);
//     req.body.password = hash;
//     let final = await user.insertOne(req.body);
//     res.json({ message: "User successfully registered" });
//   } catch (err) {
//     console.log(err);
//     res.json(err);
//   }
// });

// register
app.post("/register", async (req, res) => {
  try {
    let user = client.db("pizzaDB").collection("Registration");
    let salt = await bcrypt.genSalt(Number(process.env.SALT));
    let hash = await bcrypt.hash(req.body.password, salt);
    req.body.password = hash;
    let nameHash = await bcrypt.hash(req.body.email, salt);
    let verifySalt = await bcrypt.genSalt(Number(process.env.SALT));
    let hashID = jwt.sign({ _id: nameHash }, process.env.SECRETNAMEKEY, {
      expiresIn: "2 days",
    });
    let verifytoken = jwt.sign(
      { _id: verifySalt },
      process.env.SECRETEMAILKEY,
      {
        expiresIn: "2 days",
      }
    );
    req.body.hashID = hashID;
    req.body.token = verifytoken;
    let insertedData = await user.insertOne(req.body);
    let [getentry] = await user
      .find({ _id: insertedData.insertedId })
      .toArray();

    const verifyurl = `${process.env.BASE_URL}/${getentry.hashID}/verify/${getentry.token}`;
    await verifymail(req.body.email, "Verify Email", verifyurl);
    res.status(200).json({ message: "An email sent to your mail id" });
  } catch (err) {
    res.status(500).json({ message: `something went wrong; ${err}` });
  }
});

// verifying email

app.get("/register/:id/verify/:token", async (req, res) => {
  try {
    let user = client.db("pizzaDB").collection("Registration");
    const dataToVerify = await user.findOne({ hashID: req.params.id });
    if (!dataToVerify) return res.status(400).json({ message: "invalid link" });
    const token = await user.findOne({
      _id: dataToVerify._id,
      token: req.params.token,
    });
    if (!token) return res.status(400).json({ message: "invalid link" });
    await user.findOneAndUpdate(
      { _id: token._id },
      { $set: { verified: true, hashID: "", token: "" } }
    );
    res.status(200).json({ message: "Email verified Successfully" });
  } catch (err) {
    res.status(500).json({ message: `something went wrong; ${err}` });
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
      let type = user.usertype;
      let compare = await bcrypt.compare(req.body.password, user.password);
      if (type !== req.body.usertype)
        return res.status(401).json({
          message:
            "usertype mismatch \n select admin or user correctly bassed on your access",
        });
      if (compare && user.verified) {
        let token = jwt.sign({ _id: user._id }, process.env.SECRET, {
          expiresIn: "2 days",
        });
        res.status(200).json({ token, type });
        // res.json({ message: "logged in successfully" });
      } else {
        res.status(404).json({
          message:
            "password is wrong or email is not verified \n Kindly Check your Password or verify your Email",
        });
      }
    } else {
      res.status(404).json({ message: "user email not found" });
    }
  } catch (err) {
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.listen(process.env.PORT || 3001, () => {
  console.log("server listening on port 3001");
});

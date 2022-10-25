import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
dotenv.config();
import { MongoClient } from "mongodb";
const URL = process.env.DB;
import nodemailer from "nodemailer";

// initializing express
const app = express();

// MidleWare

app.use(express.json());

//cors

app.use(
  cors()
  // {
  //   origin: "http://localhost:3000",
  //   origin: "https://viki-pizza-delivery-app.netlify.app",
  // }
);

// Establishing connection to database

const createConnection = async () => {
  const client = new MongoClient(URL);
  await client.connect();
  console.log("MongoDB connected");
  return client;
};
const client = await createConnection();

// authenticate function

let authenticate = (req, res, next) => {
  try {
    if (req.headers.authorization) {
      let decode = jwt.verify(req.headers.authorization, process.env.SECRET);
      if (decode) {
        next();
      } else {
        res.status(401).json({ message: "Unauthorized" });
      }
    } else {
      res.status(401).json({ message: "Unauthorized" });
    }
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
};

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

// mail sender

const verifymail = async (email, subject, text) => {
  try {
    await transporter.sendMail({
      from: process.env.USER,
      to: email,
      subject: subject,
      text: text,
    });
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
};

// Web Server Check

app.get("/", (req, res) => {
  res.json({ message: "Reporting for duty" });
});

// Admin/user register

app.post("/register", async (req, res) => {
  try {
    let user = client.db("pizzaDB").collection("Registration");
    let userexists = await user.findOne({ email: req.body.email });
    if (userexists)
      return res.status(401).json({ message: "Email Already exists" });
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
    await verifymail(
      req.body.email,
      "Verify Email",
      `Hi I am form Pizza Lair,\n Please Click the below link to verify Your email \n ${verifyurl}`
    );
    res.status(200).json({ message: "An email sent to your mail id" });
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// verifying email for registration

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
    await user.findOneAndUpdate(
      { _id: token._id },
      { $unset: { hashID: "", token: "" } }
    );
    res.status(200).json({ message: "Email verified Successfully" });
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// Admin/user Login

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
      let email = user.email;
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
        res.status(200).json({ token, type, email });
      } else {
        res.status(401).json({
          message:
            "password is wrong or email is not verified \n Kindly Check your Password or verify your Email",
        });
      }
    } else {
      res.status(404).json({ message: "user email not found" });
    }
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// forgot password registration

app.post("/forpass", async (req, res) => {
  try {
    let user = client.db("pizzaDB").collection("Registration");

    let userExists = await user.findOne({ email: req.body.email });
    if (!userExists)
      return res.status(401).json({ message: "Invalid Email ID" });
    let salt = await bcrypt.genSalt(Number(process.env.SALT));
    let nameHash = await bcrypt.hash(req.body.email, salt);
    let verifySalt = await bcrypt.genSalt(Number(process.env.SALT));
    let passID = jwt.sign({ _id: nameHash }, process.env.SECRETPASSKEY, {
      expiresIn: "2 days",
    });
    let passtoken = jwt.sign({ _id: verifySalt }, process.env.SECRETEMAILKEY, {
      expiresIn: "2 days",
    });

    let insertedData = await user.findOneAndUpdate(
      { email: req.body.email },
      {
        $set: {
          passID: passID,
          passtoken: passtoken,
          passstatus: false,
        },
      }
    );
    let [getentry] = await user.find({ _id: insertedData.value._id }).toArray();

    const verifyurl = `${process.env.BASE_URL}/forpass/${getentry.passID}/verify/${getentry.passtoken}`;
    await verifymail(
      req.body.email,
      "Verify Email to reset password",
      `Hi i am form Pizza Lair, \n Please Click the below link to reset Your password \n ${verifyurl}`
    );
    res.status(200).json({ message: "An email sent to your mail id" });
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// verifying forgot password

app.get("/forpass/:id/verify/:token", async (req, res) => {
  try {
    let user = client.db("pizzaDB").collection("Registration");
    const dataToVerify = await user.findOne({ passID: req.params.id });
    if (!dataToVerify) return res.status(400).json({ message: "invalid link" });
    const token = await user.findOne({
      _id: dataToVerify._id,
      passtoken: req.params.token,
    });
    if (!token) return res.status(400).json({ message: "invalid link" });
    await user.findOneAndUpdate(
      { _id: token._id },
      { $set: { passstatus: true, passID: "", passtoken: "" } }
    );
    res.status(200).json({ message: "Email verified Successfully" });
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// reset password

app.post("/resetpass", async (req, res) => {
  try {
    //getting the data from the db for the sent email
    let user = client.db("pizzaDB").collection("Registration");

    let userExists = await user.findOne({ email: req.body.email });
    if (!userExists)
      return res.status(401).json({ message: "Invalid Email ID" });
    let salt = await bcrypt.genSalt(Number(process.env.SALT));
    let hash = await bcrypt.hash(req.body.password, salt);
    req.body.password = hash;
    if (userExists.passstatus) {
      await user.findOneAndUpdate(
        { email: req.body.email },
        { $set: { password: req.body.password } }
      );
      await user.findOneAndUpdate(
        { email: req.body.email },
        { $unset: { passstatus: "", passID: "", passtoken: "" } }
      );
      res.status(200).json({ message: "Password changed successfully" });
    } else {
      res.status(401).json({
        message:
          "Email is not verified for password reset \n Kindly verify your Email",
      });
    }
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// To add pizza varites to database for admin

app.post("/pizzas", authenticate, async (req, res) => {
  try {
    let response = await client
      .db("pizzaDB")
      .collection("Pizzas")
      .insertOne(req.body);

    if (response.acknowledged)
      return res.status(200).json({ message: "Data inserted" });
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// To get pizza varites from database

app.get("/pizzas", authenticate, async (req, res) => {
  try {
    let response = await client
      .db("pizzaDB")
      .collection("Pizzas")
      .find()
      .toArray();
    if (response) return res.status(200).json(response);
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// to post cart pizzas
app.post("/cartpizzas", authenticate, async (req, res) => {
  try {
    let response = await client
      .db("pizzaDB")
      .collection("CartPizzas")
      .insertOne(req.body);

    if (response.acknowledged) {
      res.status(200).json({
        message:
          "order-submitted, Please login to a admin account if you are a tester",
      });
    }
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// to get order details

app.get("/getcartpizzas", authenticate, async (req, res) => {
  try {
    let response = await client
      .db("pizzaDB")
      .collection("CartPizzas")
      .find()
      .toArray();

    if (response) return res.status(200).json(response);
    else res.status(401).json({ message: "something went wrong" });
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// to delete current order
app.get("/deletecartpizzas", authenticate, async (req, res) => {
  try {
    let response = await client
      .db("pizzaDB")
      .collection("CartPizzas")
      .findOneAndDelete({ orderApproved: true })
      .toArray();

    if (response) return res.status(200).json(response);
    else res.status(401).json({ message: "something went wrong" });
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// to approve order details

app.post("/approvecartpizzas", authenticate, async (req, res) => {
  try {
    let response = await client
      .db("pizzaDB")
      .collection("Inventory")
      .findOne({ title: req.body.title });
    if (response) {
      await client
        .db("pizzaDB")
        .collection("Inventory")
        .findOneAndDelete({ title: req.body.title });
    }

    let addData = await client
      .db("pizzaDB")
      .collection("Inventory")
      .insertOne(req.body);
    let orderUpdate = await client
      .db("pizzaDB")
      .collection("CartPizzas")
      .findOneAndUpdate(
        { orderApproved: false },
        { $set: { orderApproved: true } }
      );

    if (addData.acknowledged && orderUpdate)
      return res.status(200).json({ message: "Order Approved" });
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// to add inventory

app.post("/inventory", authenticate, async (req, res) => {
  try {
    let response = await client
      .db("pizzaDB")
      .collection("Inventory")
      .findOne({ title: req.body.title });
    if (response) {
      await client
        .db("pizzaDB")
        .collection("Inventory")
        .findOneAndDelete({ title: req.body.title });
    }

    let addData = await client
      .db("pizzaDB")
      .collection("Inventory")
      .insertOne(req.body);

    if (addData.acknowledged)
      return res.status(200).json({ message: "Added to Stock" });
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// to get inventory
app.get("/inventory", authenticate, async (req, res) => {
  try {
    let response = await client
      .db("pizzaDB")
      .collection("Inventory")
      .find()
      .toArray();

    if (response) return res.status(200).json(response);
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// low inventory

app.post("/lowinventory", authenticate, async (req, res) => {
  let lowstock = JSON.stringify(req.body.required);
  try {
    await verifymail(
      req.body.email,
      "Verify Email",
      `Hi I am form Pizza Lair,\n The below mentioned stocks are very low \n ${lowstock} `
    );
    res.status(200).json({
      message: "Mail sent to Your email regarding low stock, pls check",
    });
  } catch (error) {
    res.status(500).json({ message: `something went wrong; ${error}` });
  }
});

// port listen

app.listen(process.env.PORT || 3001, () => {
  console.log("server listening on port 3001");
});

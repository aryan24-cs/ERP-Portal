const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
require("dotenv").config();

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.set("view engine", "ejs");

// MongoDB Atlas Connection
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Schemas
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ["user", "admin"], default: "user" },
  details: { rollNo: String, class: String },
  attendance: [{ date: String, status: String }],
  otp: String,
  otpExpires: Date,
});

const documentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  fileType: String,
  filePath: String,
});

const User = mongoose.model("User", userSchema);
const Document = mongoose.model("Document", documentSchema);

// Nodemailer Setup
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Multer Setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "public/uploads/"),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({ storage });

// Middleware to check authentication
const authMiddleware = (role) => (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1] || req.query.token;
  if (!token) return res.redirect("/login");
  jwt.verify(token, "secret", (err, decoded) => {
    if (err || (role && decoded.role !== role)) return res.redirect("/login");
    req.user = decoded;
    next();
  });
};

// Routes
app.get("/login", (req, res) => res.render("login", { error: null }));
app.post("/login", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.render("login", { error: "User not found" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  await User.updateOne(
    { email },
    { otp, otpExpires: Date.now() + 10 * 60 * 1000 }
  );

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your OTP for ERP Portal Login",
    text: `Your OTP is ${otp}. It is valid for 10 minutes.`,
  });

  res.render("login", { error: null, otpSent: true, email });
});

app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  const user = await User.findOne({
    email,
    otp,
    otpExpires: { $gt: Date.now() },
  });
  if (!user)
    return res.render("login", { error: "Invalid or expired OTP", email });

  const token = jwt.sign({ id: user._id, role: user.role }, "secret", {
    expiresIn: "1h",
  });
  res.redirect(
    user.role === "admin" ? `/admin?token=${token}` : `/user?token=${token}`
  );
});

app.get("/register", (req, res) => res.render("register", { error: null }));
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: process.env.ADMIN_EMAILS.split(",").includes(email)
        ? "admin"
        : "user",
      details: { rollNo: "", class: "" },
      attendance: [],
    });
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Welcome to ERP Portal",
      text: `Dear ${name},\nYour account has been created successfully.`,
    });

    res.redirect("/login");
  } catch (err) {
    res.render("register", { error: "Email already exists" });
  }
});

app.get("/user", authMiddleware("user"), async (req, res) => {
  const user = await User.findById(req.user.id);
  const documents = await Document.find({ userId: req.user.id });
  res.render("user", { user, documents });
});

app.get("/admin", authMiddleware("admin"), async (req, res) => {
  const users = await User.find({ role: "user" });
  res.render("admin", { users });
});

app.post("/admin/create-user", authMiddleware("admin"), async (req, res) => {
  const { name, email, rollNo, class: userClass } = req.body;
  const password = Math.random().toString(36).slice(-8);
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: "user",
      details: { rollNo, class: userClass },
      attendance: [],
    });
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your ERP Portal Account",
      text: `Dear ${name},\nYour account has been created.\nEmail: ${email}\nPassword: ${password}`,
    });

    res.redirect("/admin");
  } catch (err) {
    res.redirect("/admin");
  }
});

app.post("/admin/edit-user", authMiddleware("admin"), async (req, res) => {
  const { userId, name, rollNo, class: userClass } = req.body;
  await User.updateOne(
    { _id: userId },
    { name, details: { rollNo, class: userClass } }
  );
  res.redirect("/admin");
});

app.post(
  "/admin/upload",
  authMiddleware("admin"),
  upload.single("file"),
  async (req, res) => {
    const { userId, fileType } = req.body;
    const document = new Document({
      userId,
      fileType,
      filePath: `uploads/${req.file.filename}`,
    });
    await document.save();

    const user = await User.findById(userId);
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: `New ${fileType} Uploaded`,
      text: `Dear ${user.name},\nYour ${fileType} has been uploaded. Please check your dashboard.`,
    });

    res.redirect("/admin");
  }
);

app.listen(3000, () => console.log("Server running on port 3000"));

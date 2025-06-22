const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const fs = require("fs"); // Added for directory creation and file cleanup
const { v2: cloudinary } = require("cloudinary");
require("dotenv").config();

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// MongoDB Atlas Connection
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, "public/uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log("Created uploads directory:", uploadDir);
}

// Multer Setup for Local Storage (Temporary)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "application/pdf"];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Invalid file type. Only JPG, PNG, and PDF are allowed."));
    }
  },
});

// Schemas
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ["user", "admin"], default: "user" },
  details: {
    rollNo: String,
    class: String,
    phone: String,
    dob: String,
    fatherName: String,
    motherName: String,
    address: String,
  },
  attendance: [{ date: String, status: String }],
  otp: String,
  otpExpires: Date,
});

const documentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  fileType: String,
  fileUrl: String,
  publicId: String,
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

// Authentication Middleware
const authMiddleware = (role) => (req, res, next) => {
  const token =
    req.headers["authorization"]?.split(" ")[1] ||
    req.query.token ||
    req.body.token;
  if (!token) {
    console.error("Auth Middleware: No token provided");
    return res.redirect("/login?error=No token provided");
  }
  jwt.verify(token, "secret", (err, decoded) => {
    if (err) {
      console.error("Auth Middleware: Token verification failed", err.message);
      return res.redirect("/login?error=Invalid or expired token");
    }
    if (role && decoded.role !== role) {
      console.error(
        `Auth Middleware: Role mismatch, expected ${role}, got ${decoded.role}`
      );
      return res.redirect("/login?error=Unauthorized access");
    }
    req.user = decoded;
    next();
  });
};

// Routes
app.get("/", (req, res) => res.render("index"));

app.get("/login", (req, res) => {
  const error = req.query.error || null;
  res.render("login", { error });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.render("login", { error: "Invalid email or password" });
  }
  const token = jwt.sign({ id: user._id, role: user.role }, "secret", {
    expiresIn: "1h",
  });
  res.redirect(
    user.role === "admin" ? `/admin?token=${token}` : `/user?token=${token}`
  );
});

app.get("/forgot-password", (req, res) =>
  res.render("forgot-password", { error: null })
);

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.render("forgot-password", { error: "Email not found" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  await User.updateOne(
    { email },
    { otp, otpExpires: Date.now() + 10 * 60 * 1000 }
  );

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Password Reset OTP",
    text: `Your OTP is ${otp}. It is valid for 10 minutes.`,
  });

  res.render("verify-otp", { email, error: null });
});

app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  const user = await User.findOne({
    email,
    otp,
    otpExpires: { $gt: Date.now() },
  });
  if (!user)
    return res.render("verify-otp", { email, error: "Invalid or expired OTP" });

  res.render("reset-password", { email, error: null });
});

app.post("/reset-password", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  await User.updateOne(
    { email },
    { password: hashedPassword, otp: null, otpExpires: null }
  );
  res.redirect("/login");
});

app.get("/user", authMiddleware("user"), async (req, res) => {
  const user = await User.findById(req.user.id);
  const documents = await Document.find({ userId: req.user.id });
  res.render("user", { user, documents, success: null });
});

app.post("/user/update-profile", authMiddleware("user"), async (req, res) => {
  const { phone, address } = req.body;
  await User.updateOne(
    { _id: req.user.id },
    { "details.phone": phone, "details.address": address }
  );
  const user = await User.findById(req.user.id);
  const documents = await Document.find({ userId: req.user.id });
  res.render("user", {
    user,
    documents,
    success: "Profile updated successfully",
  });
});

app.get("/admin", authMiddleware("admin"), async (req, res) => {
  const users = await User.find({ role: "user" });
  console.log("Users fetched for admin:", users.length); // Debug
  const token = req.query.token || "";
  res.render("admin", { users, error: null, token });
});

app.post("/admin/create-user", authMiddleware("admin"), async (req, res) => {
  const {
    name,
    email,
    rollNo,
    class: userClass,
    phone,
    dob,
    fatherName,
    motherName,
    address,
  } = req.body;
  let password = Math.random().toString(36).slice(-8);
  if (process.env.ADMIN_EMAILS.split(",").includes(email)) {
    password = process.env.ADMIN_PASSWORD;
  }
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: process.env.ADMIN_EMAILS.split(",").includes(email)
        ? "admin"
        : "user",
      details: {
        rollNo,
        class: userClass,
        phone,
        dob,
        fatherName,
        motherName,
        address,
      },
      attendance: [],
    });
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your ERP Portal Account",
      text: `Dear ${name},\nYour account has been created.\nEmail: ${email}\nPassword: ${password}`,
    });

    const users = await User.find({ role: "user" });
    const token = req.body.token || req.query.token || "";
    res.render("admin", { users, error: null, token });
  } catch (err) {
    const users = await User.find({ role: "user" });
    const token = req.body.token || req.query.token || "";
    res.render("admin", { users, error: "Email already exists", token });
  }
});

app.post("/admin/edit-user", authMiddleware("admin"), async (req, res) => {
  const {
    userId,
    name,
    rollNo,
    class: userClass,
    phone,
    dob,
    fatherName,
    motherName,
    address,
  } = req.body;
  await User.updateOne(
    { _id: userId },
    {
      name,
      details: {
        rollNo,
        class: userClass,
        phone,
        dob,
        fatherName,
        motherName,
        address,
      },
    }
  );
  const users = await User.find({ role: "user" });
  const token = req.body.token || req.query.token || "";
  res.render("admin", { users, error: null, token });
});

app.post(
  "/admin/upload",
  upload.single("file"),
  authMiddleware("admin"),
  async (req, res) => {
    const { userId, fileType } = req.body;
    const token = req.body.token || req.query.token || "";
    const users = await User.find({ role: "user" });

    if (!req.file) {
      console.error("Upload error: No file uploaded");
      return res.render("admin", {
        users,
        error: "No file uploaded. Please select a JPG, PNG, or PDF file.",
        token,
      });
    }

    try {
      // Verify file exists
      if (!fs.existsSync(req.file.path)) {
        console.error("Upload error: File not found at", req.file.path);
        return res.render("admin", {
          users,
          error: "File could not be saved locally. Please try again.",
          token,
        });
      }

      const uploadResult = await cloudinary.uploader.upload(req.file.path, {
        folder: "erp-portal",
        resource_type: "auto",
        allowed_formats: ["jpg", "png", "pdf"],
      });

      const document = new Document({
        userId,
        fileType,
        fileUrl: uploadResult.secure_url,
        publicId: uploadResult.public_id,
      });
      await document.save();

      const user = await User.findById(userId);
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: `New ${fileType} Uploaded`,
        text: `Dear ${user.name},\nYour ${fileType} has been uploaded. Please check your dashboard.`,
      });

      // Clean up temporary file
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("File deletion error:", err);
        else console.log("Deleted temporary file:", req.file.path);
      });

      res.render("admin", { users, error: null, token });
    } catch (err) {
      console.error("Cloudinary upload error:", err);
      // Clean up temporary file on error
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("File deletion error:", err);
        });
      }
      res.render("admin", {
        users,
        error: "File upload failed: " + err.message,
        token,
      });
    }
  }
);

app.post(
  "/admin/mark-attendance",
  authMiddleware("admin"),
  async (req, res) => {
    const { userId, date, status } = req.body;
    const token = req.body.token || req.query.token || "";
    try {
      await User.updateOne(
        { _id: userId },
        { $push: { attendance: { date, status } } }
      );
      const users = await User.find({ role: "user" });
      res.render("admin", { users, error: null, token });
    } catch (err) {
      console.error("Attendance marking error:", err);
      const users = await User.find({ role: "user" });
      res.render("admin", { users, error: "Failed to mark attendance", token });
    }
  }
);

app.listen(3000, () => console.log("Server running on port 3000"));

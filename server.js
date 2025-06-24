const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { v2: cloudinary } = require("cloudinary");
const axios = require("axios");
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
  course: String,
  branch: String,
  semester: Number,
  subjects: [String],
  teachers: [
    {
      teacherId: { type: mongoose.Schema.Types.ObjectId, ref: "Teacher" },
      subject: String,
    },
  ],
  details: {
    rollNo: { type: String, unique: true },
    class: String,
    phone: String,
    dob: String,
    fatherName: String,
    motherName: String,
    address: String,
  },
  attendance: [
    {
      date: String,
      status: String,
      subject: String,
    },
  ],
  otp: String,
  otpExpires: Date,
});

const documentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  fileType: String,
  fileUrl: String,
  publicId: String,
  semester: String,
  createdAt: { type: Date, default: Date.now },
  studentName: String,
});

const teacherSchema = new mongoose.Schema({
  name: String,
  subject: String,
});

const User = mongoose.model("User", userSchema);
const Document = mongoose.model("Document", documentSchema);
const Teacher = mongoose.model("Teacher", teacherSchema);

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
    user.role === "admin"
      ? `/admin?token=${token}`
      : `/users/user?token=${token}`
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

app.get("/users/user", authMiddleware("user"), async (req, res) => {
  const user = await User.findById(req.user.id);
  const sixMonthsAgo = new Date();
  sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
  const documents = await Document.find({
    userId: req.user.id,
    createdAt: { $gte: sixMonthsAgo },
  });
  const token = req.query.token || "";
  res.render("users/user", {
    user,
    documents,
    success: null,
    error: null,
    token,
  });
});

app.get("/users/attendance", authMiddleware("user"), async (req, res) => {
  const user = await User.findById(req.user.id);
  const subjects = [
    ...new Set(user.attendance.map((a) => a.subject).filter((s) => s)),
  ];
  const attendanceBySubject = subjects.map((subject) => {
    const records = user.attendance.filter((a) => a.subject === subject);
    const present = records.filter((r) => r.status === "Present").length;
    const total = records.length;
    return { subject, present, absent: total - present, total };
  });
  const token = req.query.token || "";
  res.render("users/attendance", { user, attendanceBySubject, token });
});

app.get("/users/teachers", authMiddleware("user"), async (req, res) => {
  const user = await User.findById(req.user.id).populate("teachers.teacherId");
  const token = req.query.token || "";
  res.render("users/teachers", { user, token });
});

app.get("/users/documents", authMiddleware("user"), async (req, res) => {
  const user = await User.findById(req.user.id);
  const documents = await Document.find({ userId: req.user.id });
  const token = req.query.token || "";
  res.render("users/documents", { user, documents, token });
});

app.post("/users/update-profile", authMiddleware("user"), async (req, res) => {
  const { phone, address } = req.body;
  const user = await User.findById(req.user.id);
  const sixMonthsAgo = new Date();
  sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
  const documents = await Document.find({
    userId: req.user.id,
    createdAt: { $gte: sixMonthsAgo },
  });
  const token = req.body.token || req.query.token || "";

  // Validate phone
  const phonePattern = /^\d{10,15}$/;
  if (!phonePattern.test(phone.trim())) {
    return res.render("users/user", {
      user,
      documents,
      success: null,
      error: "Phone number must be 10-15 digits",
      token,
    });
  }

  // Validate address
  if (!address.trim()) {
    return res.render("users/user", {
      user,
      documents,
      success: null,
      error: "Address is required",
      token,
    });
  }
  if (address.length > 200) {
    return res.render("users/user", {
      user,
      documents,
      success: null,
      error: "Address cannot exceed 200 characters",
      token,
    });
  }

  try {
    await User.updateOne(
      { _id: req.user.id },
      { "details.phone": phone.trim(), "details.address": address.trim() }
    );
    const updatedUser = await User.findById(req.user.id);
    res.render("users/user", {
      user: updatedUser,
      documents,
      success: "Profile updated successfully",
      error: null,
      token,
    });
  } catch (err) {
    console.error("Profile update error:", err);
    res.render("users/user", {
      user,
      documents,
      success: null,
      error: "Failed to update profile. Please try again.",
      token,
    });
  }
});

app.get(
  "/users/download/:publicId",
  authMiddleware("user"),
  async (req, res) => {
    try {
      const { publicId } = req.params;
      console.log("Download requested for publicId:", publicId);
      const doc = await Document.findOne({ publicId, userId: req.user.id });
      if (!doc) {
        console.error(
          "Document not found for publicId:",
          publicId,
          "userId:",
          req.user.id
        );
        return res.status(404).render("users/user", {
          user: await User.findById(req.user.id),
          documents: await Document.find({
            userId: req.user.id,
            createdAt: {
              $gte: new Date(new Date().setMonth(new Date().getMonth() - 6)),
            },
          }),
          success: null,
          error: "Document not found or you do not have access",
          token: req.query.token || "",
        });
      }

      const response = await axios.get(doc.fileUrl, { responseType: "stream" });
      const fileName = `${doc.fileType}-${doc.semester}.${doc.fileUrl
        .split(".")
        .pop()}`;
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${fileName}"`
      );
      res.setHeader("Content-Type", response.headers["content-type"]);
      response.data.pipe(res);
    } catch (err) {
      console.error("Download error:", err.message);
      res.status(500).render("users/user", {
        user: await User.findById(req.user.id),
        documents: await Document.find({
          userId: req.user.id,
          createdAt: {
            $gte: new Date(new Date().setMonth(new Date().getMonth() - 6)),
          },
        }),
        success: null,
        error: "Failed to download file. Please try again.",
        token: req.query.token || "",
      });
    }
  }
);

app.get('/admin', authMiddleware('admin'), async (req, res) => {
  try {
    const users = await User.find({ role: 'user' });
    const admin = await User.findById(req.user.id).select('name email');
    console.log('Users fetched for admin:', users.length);
    const token = req.query.token || '';
    res.render('admin', { users, admin, error: null, token });
  } catch (err) {
    console.error('Error fetching admin data:', err);
    res.render('admin', { users: [], admin: null, error: err.message, token: req.query.token || '' });
  }
});


app.get("/admin/create-user", authMiddleware("admin"), (req, res) => {
  res.render("admin/create-user", { token: req.query.token, error: null });
});

app.post("/admin/create-user", authMiddleware("admin"), async (req, res) => {
  const {
    name,
    email,
    rollNo,
    course,
    branch,
    semester,
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
      course,
      branch,
      semester: Number(semester),
      details: { rollNo, phone, dob, fatherName, motherName, address },
      attendance: [],
      subjects: [],
      teachers: [],
    });
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your ERP Portal Account",
      text: `Dear ${name},\nYour account has been created.\nEmail: ${email}\nPassword: ${password}`,
    });

    res.redirect(`/admin/create-user?token=${req.query.token}`);
  } catch (err) {
    res.render("admin/create-user", {
      token: req.query.token,
      error: err.message,
    });
  }
});

app.get("/admin/make-attendance", authMiddleware("admin"), (req, res) => {
  res.render("admin/make-attendance", { token: req.query.token, error: null });
});

app.post(
  "/admin/mark-attendance",
  authMiddleware("admin"),
  async (req, res) => {
    const { date, course, branch, semester, studentId, subject, status } =
      req.body;
    const token = req.body.token || req.query.token || "";
    try {
      const user = await User.findById(studentId);
      if (!user)
        return res.render("admin/make-attendance", {
          token,
          error: "Student not found",
        });
      user.attendance.push({ date, subject, status });
      await user.save();
      res.redirect(`/admin/make-attendance?token=${token}`);
    } catch (err) {
      console.error("Attendance marking error:", err);
      res.render("admin/make-attendance", { token, error: err.message });
    }
  }
);

app.get("/admin/edit-user", authMiddleware("admin"), async (req, res) => {
  try {
    const users = await User.find({ role: "user" });
    res.render("admin/edit-user", {
      token: req.query.token,
      users,
      error: null,
    });
  } catch (err) {
    res.render("admin/edit-user", {
      token: req.query.token,
      users: [],
      error: err.message,
    });
  }
});

app.post("/admin/edit-user", authMiddleware("admin"), async (req, res) => {
  const {
    userId,
    name,
    email,
    rollNo,
    course,
    branch,
    semester,
    phone,
    dob,
    fatherName,
    motherName,
    address,
  } = req.body;
  const token = req.body.token || req.query.token || "";
  try {
    await User.findByIdAndUpdate(userId, {
      name,
      email,
      course,
      branch,
      semester: Number(semester),
      details: { rollNo, phone, dob, fatherName, motherName, address },
    });
    res.redirect(`/admin/edit-user?token=${token}`);
  } catch (err) {
    const users = await User.find({ role: "user" });
    res.render("admin/edit-user", { token, users, error: err.message });
  }
});

app.get("/admin/upload-documents", authMiddleware("admin"), (req, res) => {
  res.render("admin/upload-documents", { token: req.query.token, error: null });
});

app.post(
  "/admin/upload-documents",
  authMiddleware("admin"),
  upload.single("file"),
  async (req, res) => {
    const { course, branch, semester, studentId, fileType } = req.body;
    const token = req.body.token || req.query.token || "";
    if (!req.file) {
      console.error("Upload error: No file uploaded");
      return res.render("admin/upload-documents", {
        token,
        error: "No file uploaded. Please select a JPG, PNG, or PDF file.",
      });
    }

    try {
      if (!fs.existsSync(req.file.path)) {
        console.error("Upload error: File not found at", req.file.path);
        return res.render("admin/upload-documents", {
          token,
          error: "File could not be saved locally. Please try again.",
        });
      }

      const uploadResult = await cloudinary.uploader.upload(req.file.path, {
        folder: "erp-portal",
        resource_type: "auto",
        allowed_formats: ["jpg", "png", "pdf"],
      });

      const user = await User.findById(studentId);
      if (!user)
        return res.render("admin/upload-documents", {
          token,
          error: "Student not found",
        });

      const document = new Document({
        userId: studentId,
        fileType,
        fileUrl: uploadResult.secure_url,
        publicId: uploadResult.public_id,
        semester,
        studentName: user.name,
      });
      await document.save();

      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: `New ${fileType} Uploaded`,
        text: `Dear ${user.name},\nYour ${fileType} for semester ${semester} has been uploaded. Please check your dashboard.`,
      });

      fs.unlink(req.file.path, (err) => {
        if (err) console.error("File deletion error:", err);
        else console.log("Deleted temporary file:", req.file.path);
      });

      res.redirect(`/admin/upload-documents?token=${token}`);
    } catch (err) {
      console.error("Cloudinary upload error:", err);
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("File deletion error:", err);
        });
      }
      res.render("admin/upload-documents", {
        token,
        error: "File upload failed: " + err.message,
      });
    }
  }
);

app.get("/admin/assign-teachers", authMiddleware("admin"), async (req, res) => {
  try {
    const teachers = await Teacher.find();
    res.render("admin/assign-teachers", {
      token: req.query.token,
      teachers,
      error: null,
    });
  } catch (err) {
    res.render("admin/assign-teachers", {
      token: req.query.token,
      teachers: [],
      error: err.message,
    });
  }
});

app.post("/admin/create-teacher", authMiddleware("admin"), async (req, res) => {
  const { name, subject } = req.body;
  const token = req.body.token || req.query.token || "";
  try {
    const teacher = new Teacher({ name, subject });
    await teacher.save();
    res.redirect(`/admin/assign-teachers?token=${token}`);
  } catch (err) {
    const teachers = await Teacher.find();
    res.render("admin/assign-teachers", {
      token,
      teachers,
      error: err.message,
    });
  }
});

app.post("/admin/assign-teacher", authMiddleware("admin"), async (req, res) => {
  const { studentId, teacherId, subject } = req.body;
  const token = req.body.token || req.query.token || "";
  try {
    const user = await User.findById(studentId);
    const teacher = await Teacher.findById(teacherId);
    if (!user || !teacher) {
      const teachers = await Teacher.find();
      return res.render("admin/assign-teachers", {
        token,
        teachers,
        error: "Student or teacher not found",
      });
    }
    if (!user.subjects.includes(subject)) user.subjects.push(subject);
    user.teachers.push({ teacherId, subject });
    await user.save();
    res.redirect(`/admin/assign-teachers?token=${token}`);
  } catch (err) {
    const teachers = await Teacher.find();
    res.render("admin/assign-teachers", {
      token,
      teachers,
      error: err.message,
    });
  }
});

app.get("/api/students", authMiddleware("admin"), async (req, res) => {
  try {
    const { course, branch, semester } = req.query;
    const students = await User.find({
      role: "user",
      course,
      branch,
      semester: Number(semester),
    });
    res.json(students);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get(
  "/api/students/:id/subjects",
  authMiddleware("admin"),
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ error: "Student not found" });
      res.json(user.subjects || []);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

app.get(
  "/api/students/:id/documents",
  authMiddleware("admin"),
  async (req, res) => {
    try {
      const documents = await Document.find({ userId: req.params.id });
      res.json(documents || []);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

app.get(
  "/api/students/:id/attendance",
  authMiddleware("admin"),
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ error: "Student not found" });
      res.json(user.attendance || []);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

app.get("/api/users/:id", authMiddleware("admin"), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));

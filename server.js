const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { v2: cloudinary } = require("cloudinary");
const moment = require("moment");
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
      assignedAt: { type: Date, default: Date.now },
    },
  ],
  details: {
    rollNo: { type: String, unique: true },
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
  originalFilename: String,
  semester: String,
  createdAt: { type: Date, default: Date.now },
  studentName: String,
});

const teacherSchema = new mongoose.Schema({
  name: String,
  subject: String,
});

const ActivitySchema = new mongoose.Schema({
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Document = mongoose.model("Document", documentSchema);
const Teacher = mongoose.model("Teacher", teacherSchema);
const Activity = mongoose.model("Activity", ActivitySchema);

// Nodemailer Setup
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Send Email Function
const sendEmail = async (to, subject, text) => {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to,
      subject,
      text,
    });
    console.log(`Email sent to ${to}`);
  } catch (err) {
    console.error(`Error sending email to ${to}:`, err);
    throw new Error("Failed to send email: " + err.message);
  }
};

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

  await sendEmail(
    email,
    "Password Reset OTP",
    `Your OTP is ${otp}. It is valid for 10 minutes.`
  );

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

app.get("/users/update-profile", authMiddleware("user"), async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.redirect("/login?error=User not found");
    }
    const token = req.query.token || "";
    res.render("users/update-profile", {
      user,
      token,
      success: req.query.success || null,
      error: req.query.error || null,
    });
  } catch (err) {
    console.error("Error rendering update-profile page:", err);
    res.redirect(
      `/login?error=${encodeURIComponent(
        "Failed to load profile page: " + err.message
      )}`
    );
  }
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
    return res.redirect(
      `/users/update-profile?token=${token}&error=${encodeURIComponent(
        "Phone number must be 10-15 digits"
      )}`
    );
  }

  // Validate address
  if (!address.trim()) {
    return res.redirect(
      `/users/update-profile?token=${token}&error=${encodeURIComponent(
        "Address is required"
      )}`
    );
  }
  if (address.length > 200) {
    return res.redirect(
      `/users/update-profile?token=${token}&error=${encodeURIComponent(
        "Address cannot exceed 200 characters"
      )}`
    );
  }

  try {
    await User.updateOne(
      { _id: req.user.id },
      { "details.phone": phone.trim(), "details.address": address.trim() }
    );
    res.redirect(
      `/users/update-profile?token=${token}&success=${encodeURIComponent(
        "Profile updated successfully"
      )}`
    );
  } catch (err) {
    console.error("Profile update error:", err);
    res.redirect(
      `/users/update-profile?token=${token}&error=${encodeURIComponent(
        "Failed to update profile. Please try again."
      )}`
    );
  }
});

app.get("/users/download/:publicId", authMiddleware(), async (req, res) => {
  try {
    const publicId = req.params.publicId;
    const document = await Document.findOne({
      publicId: `erp-portal/${publicId}`,
    });
    if (!document) {
      console.error("Document not found for publicId:", publicId);
      return res.status(404).send("Document not found");
    }

    // Fetch the file from Cloudinary
    const response = await axios.get(document.fileUrl, {
      responseType: "stream",
    });

    // Set content type based on fileType
    let contentType;
    switch (document.fileType.toLowerCase()) {
      case "pdf":
        contentType = "application/pdf";
        break;
      case "image":
      case "jpg":
      case "jpeg":
        contentType = "image/jpeg";
        break;
      case "png":
        contentType = "image/png";
        break;
      default:
        contentType = "application/octet-stream";
    }

    // Set headers for download
    res.set({
      "Content-Type": contentType,
      "Content-Disposition": `attachment; filename="${
        document.originalFilename || document.fileType
      }"`,
    });

    // Stream the file to the client
    response.data.pipe(res);
  } catch (err) {
    console.error("Error downloading document:", err);
    res
      .status(500)
      .json({ error: "Failed to download document: " + err.message });
  }
});

app.get("/api/documents/recent", authMiddleware(), async (req, res) => {
  try {
    const documents = await Document.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .select(
        "studentName userId fileType semester publicId createdAt originalFilename"
      );
    res.json(documents);
  } catch (err) {
    console.error("Error fetching recent documents:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch recent documents: " + err.message });
  }
});

app.get("/admin/users", authMiddleware(), async (req, res) => {
  try {
    const users = await User.find({ role: "user" })
      .sort({ createdAt: -1 })
      .select("name email course branch semester details.rollNo createdAt");
    res.render("admin/users", { token: req.query.token, users });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.redirect(
      `/admin/users?token=${req.query.token}&error=${encodeURIComponent(
        "Failed to fetch users: " + err.message
      )}`
    );
  }
});

app.get("/admin", authMiddleware("admin"), async (req, res) => {
  try {
    const admin = await User.findById(req.user.id).select("name email role");
    if (!admin) {
      return res.redirect(
        `/login?error=${encodeURIComponent("Admin user not found")}`
      );
    }
    const activities = await Activity.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .select("message createdAt");
    res.render("admin", {
      token: req.query.token,
      admin,
      activities,
      success: req.query.success || null,
      error: req.query.error || null,
      currentPage: "admin",
    });
  } catch (err) {
    console.error("Error rendering admin dashboard:", err);
    res.redirect(
      `/login?error=${encodeURIComponent(
        "Failed to load dashboard: " + err.message
      )}`
    );
  }
});

app.get("/admin/create-user", authMiddleware("admin"), (req, res) => {
  res.render("admin/create-user", {
    token: req.query.token,
    error: req.query.error,
    success: req.query.success,
  });
});

app.post("/admin/create-user", authMiddleware("admin"), async (req, res) => {
  try {
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

    if (
      !name ||
      !email ||
      !rollNo ||
      !course ||
      !branch ||
      !semester ||
      !phone ||
      !dob ||
      !fatherName ||
      !motherName ||
      !address
    ) {
      return res.redirect(
        `/admin/create-user?token=${req.query.token}&error=${encodeURIComponent(
          "All fields are required"
        )}`
      );
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { "details.rollNo": rollNo }],
    });
    if (existingUser) {
      return res.redirect(
        `/admin/create-user?token=${req.query.token}&error=${encodeURIComponent(
          "Email or Roll Number already exists"
        )}`
      );
    }

    const password = Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: "user",
      course,
      branch,
      semester: parseInt(semester),
      details: {
        rollNo,
        phone,
        dob: new Date(dob),
        fatherName,
        motherName,
        address,
      },
      createdAt: new Date(),
    });

    await user.save();

    await new Activity({
      message: `User ${name} created by admin ${req.user.email}`,
    }).save();

    await sendEmail(
      email,
      "Your ERP Portal Account",
      `Your account has been created. Username: ${email}, Password: ${password}`
    );

    res.redirect(
      `/admin/create-user?token=${req.query.token}&success=${encodeURIComponent(
        `User ${name} created successfully`
      )}`
    );
  } catch (err) {
    console.error("Error creating user:", err);
    res.redirect(
      `/admin/create-user?token=${req.query.token}&error=${encodeURIComponent(
        "Failed to create user: " + err.message
      )}`
    );
  }
});

app.get("/api/users/recent", authMiddleware(), async (req, res) => {
  try {
    const users = await User.find({ role: "user" })
      .sort({ createdAt: -1 })
      .limit(5)
      .select("name email course branch semester details.rollNo createdAt");
    res.json(users);
  } catch (err) {
    console.error("Error fetching recent users:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch recent users: " + err.message });
  }
});

app.get("/admin/make-attendance", authMiddleware("admin"), async (req, res) => {
  try {
    const recentAttendance = await User.aggregate([
      { $unwind: "$attendance" },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id",
          as: "student",
        },
      },
      { $unwind: "$student" },
      {
        $project: {
          studentId: "$student._id",
          studentName: "$student.name",
          subject: "$attendance.subject",
          date: "$attendance.date",
          status: "$attendance.status",
        },
      },
      { $sort: { date: -1 } },
      { $limit: 5 },
    ]);
    res.render("admin/make-attendance", {
      token: req.query.token,
      error: req.query.error || null,
      success: req.query.success || null,
      recentAttendance,
    });
  } catch (err) {
    console.error("Error fetching recent attendance:", err);
    res.render("admin/make-attendance", {
      token: req.query.token,
      error: err.message,
      success: null,
      recentAttendance: [],
    });
  }
});

app.post(
  "/admin/mark-attendance",
  authMiddleware("admin"),
  async (req, res) => {
    const { date, course, branch, semester, studentId, subject, status } =
      req.body;
    const token = req.body.token || req.query.token || "";
    try {
      const normalizedDate = moment(date, ["YYYY-MM-DD", "MM/DD/YYYY"], true);
      if (!normalizedDate.isValid()) {
        return res.render("admin/make-attendance", {
          token,
          error: "Invalid date format. Please use YYYY-MM-DD or MM/DD/YYYY.",
          success: null,
          recentAttendance: [],
        });
      }
      const formattedDate = normalizedDate.format("YYYY-MM-DD");

      const user = await User.findById(studentId);
      if (!user) {
        return res.render("admin/make-attendance", {
          token,
          error: "Student not found",
          success: null,
          recentAttendance: [],
        });
      }
      user.attendance.push({ date: formattedDate, subject, status });
      await user.save();

      await new Activity({
        message: `Attendance marked for ${user.name} (${subject}: ${status}) by admin ${req.user.email}`,
      }).save();

      res.redirect(
        `/admin/make-attendance?token=${token}&success=Attendance marked for ${user.name} (${subject}: ${status})`
      );
    } catch (err) {
      console.error("Attendance marking error:", err);
      res.render("admin/make-attendance", {
        token,
        error: err.message,
        success: null,
        recentAttendance: [],
      });
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

    await new Activity({
      message: `User ${name} updated by admin ${req.user.email}`,
    }).save();

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
        success: null,
      });
    }

    try {
      if (!fs.existsSync(req.file.path)) {
        console.error("Upload error: File not found at", req.file.path);
        return res.render("admin/upload-documents", {
          token,
          error: "File could not be saved locally. Please try again.",
          success: null,
        });
      }

      const uploadResult = await cloudinary.uploader.upload(req.file.path, {
        folder: "erp-portal",
        resource_type: "auto",
        allowed_formats: ["jpg", "png", "pdf"],
      });

      const user = await User.findById(studentId);
      if (!user) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("File deletion error:", err);
        });
        return res.render("admin/upload-documents", {
          token,
          error: "Student not found",
          success: null,
        });
      }

      const document = new Document({
        userId: studentId,
        fileType,
        fileUrl: uploadResult.secure_url,
        publicId: uploadResult.public_id,
        originalFilename: req.file.originalname,
        semester,
        studentName: user.name,
      });
      await document.save();

      await new Activity({
        message: `Document ${fileType} uploaded for ${user.name} (Semester ${semester}) by admin ${req.user.email}`,
      }).save();

      await sendEmail(
        user.email,
        `New ${fileType} Uploaded`,
        `Dear ${user.name},\nYour ${fileType} for semester ${semester} has been uploaded. Please check your dashboard.`
      );

      fs.unlink(req.file.path, (err) => {
        if (err) console.error("File deletion error:", err);
        else console.log("Deleted temporary file:", req.file.path);
      });

      res.redirect(
        `/admin/upload-documents?token=${token}&success=Document ${fileType} uploaded for ${user.name} (Semester ${semester})`
      );
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
        success: null,
      });
    }
  }
);

app.get("/admin/college", authMiddleware("admin"), async (req, res) => {
  try {
    const token = req.query.token || "";
    const students = await User.find({ role: "user" }).select(
      "name email course branch semester details"
    );
    const teachers = await Teacher.find().select("name subject");
    const courses = await User.aggregate([
      { $match: { role: "user", course: { $ne: null } } },
      { $group: { _id: "$course", studentCount: { $sum: 1 } } },
      { $project: { name: "$_id", studentCount: 1, _id: 0 } },
      { $sort: { name: 1 } },
    ]);
    const branches = await User.aggregate([
      {
        $match: { role: "user", course: { $ne: null }, branch: { $ne: null } },
      },
      {
        $group: {
          _id: { course: "$course", branch: "$branch" },
          studentCount: { $sum: 1 },
        },
      },
      {
        $project: {
          course: "$_id.course",
          name: "$_id.branch",
          studentCount: 1,
          _id: 0,
        },
      },
      { $sort: { course: 1, name: 1 } },
    ]);
    const assignments = await User.aggregate([
      { $match: { role: "user", teachers: { $ne: [] } } },
      { $unwind: "$teachers" },
      {
        $lookup: {
          from: "teachers",
          localField: "teachers.teacherId",
          foreignField: "_id",
          as: "teacher",
        },
      },
      { $unwind: "$teacher" },
      {
        $project: {
          teacherId: "$teachers.teacherId",
          teacherName: "$teacher.name",
          subject: "$teachers.subject",
          studentName: "$name",
          studentId: "$_id",
          course: "$course",
          branch: "$branch",
          semester: "$semester",
          assignedAt: "$teachers.assignedAt",
        },
      },
      { $sort: { assignedAt: -1 } },
    ]);
    res.render("admin/college", {
      token,
      courses: courses || [],
      branches: branches || [],
      students: students || [],
      teachers: teachers || [],
      assignments: assignments || [],
      success: req.query.success || null,
      error: req.query.error || null,
      currentPage: "college",
    });
  } catch (err) {
    console.error("Error rendering college structure:", err);
    res.redirect(
      `/admin?token=${req.query.token}&error=${encodeURIComponent(
        "Failed to load college structure: " + err.message
      )}`
    );
  }
});

app.get("/admin/assign-teachers", authMiddleware("admin"), async (req, res) => {
  try {
    const teachers = await Teacher.find();
    const recentAssignments = await User.aggregate([
      { $unwind: "$teachers" },
      {
        $lookup: {
          from: "teachers",
          localField: "teachers.teacherId",
          foreignField: "_id",
          as: "teacher",
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id",
          as: "student",
        },
      },
      { $unwind: "$teacher" },
      { $unwind: "$student" },
      {
        $project: {
          teacherId: "$teachers.teacherId",
          teacherName: "$teacher.name",
          subject: "$teachers.subject",
          studentName: "$student.name",
          studentId: "$student._id",
          assignedAt: "$teachers.assignedAt",
        },
      },
      { $sort: { assignedAt: -1 } },
      { $limit: 5 },
    ]);
    res.render("admin/assign-teachers", {
      token: req.query.token,
      teachers,
      recentAssignments,
      error: req.query.error || null,
      success: req.query.success || null,
    });
  } catch (err) {
    res.render("admin/assign-teachers", {
      token: req.query.token,
      teachers: [],
      recentAssignments: [],
      error: err.message,
      success: null,
    });
  }
});

app.post("/admin/create-teacher", authMiddleware("admin"), async (req, res) => {
  const { name, subject } = req.body;
  const token = req.body.token || req.query.token || "";
  try {
    if (!name || !subject) {
      return res.render("admin/assign-teachers", {
        token,
        teachers: await Teacher.find(),
        recentAssignments: [],
        error: "Name and subject are required",
        success: null,
      });
    }
    const existingTeacher = await Teacher.findOne({ name, subject });
    if (existingTeacher) {
      return res.render("admin/assign-teachers", {
        token,
        teachers: await Teacher.find(),
        recentAssignments: [],
        error: `Teacher ${name} already exists for ${subject}`,
        success: null,
      });
    }
    const teacher = new Teacher({ name, subject });
    await teacher.save();

    await new Activity({
      message: `Teacher ${name} (${subject}) created by admin ${req.user.email}`,
    }).save();

    res.redirect(
      `/admin/assign-teachers?token=${token}&success=Teacher ${name} created successfully`
    );
  } catch (err) {
    res.render("admin/assign-teachers", {
      token,
      teachers: await Teacher.find(),
      recentAssignments: [],
      error: `Failed to create teacher: ${err.message}`,
      success: null,
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
      return res.redirect(
        `/admin/assign-teachers?token=${token}&error=Student or teacher not found`
      );
    }
    if (!user.subjects.includes(subject)) {
      user.subjects.push(subject);
    }
    const existingAssignment = user.teachers.find(
      (t) => t.teacherId.toString() === teacherId && t.subject === subject
    );
    if (existingAssignment) {
      return res.redirect(
        `/admin/assign-teachers?token=${token}&error=Teacher ${teacher.name} already assigned to ${user.name} for ${subject}`
      );
    }
    user.teachers.push({ teacherId, subject, assignedAt: new Date() });
    await user.save();

    await new Activity({
      message: `Teacher ${teacher.name} (${subject}) assigned to ${user.name} by admin ${req.user.email}`,
    }).save();

    res.redirect(
      `/admin/assign-teachers?token=${token}&success=Teacher ${teacher.name} (${subject}) successfully assigned to ${user.name}`
    );
  } catch (err) {
    res.redirect(
      `/admin/assign-teachers?token=${token}&error=Failed to assign teacher: ${err.message}`
    );
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

app.get("/api/students/:id/documents", authMiddleware(), async (req, res) => {
  try {
    const documents = await Document.find({ userId: req.params.id }).select(
      "studentName userId fileType semester fileUrl publicId createdAt originalFilename"
    );
    res.json(documents);
  } catch (err) {
    console.error("Error fetching documents:", err);
    res.status(500).json({ error: err.message });
  }
});

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

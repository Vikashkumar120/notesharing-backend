// server.js - Complete Node.js + Express + MongoDB server with JWT auth and Render deployment
// ==================== REQUIRES SECTION ====================
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { PDFDocument, rgb } = require('pdf-lib');
const nodemailer = require('nodemailer');
require('dotenv').config();
// ==================== APP INITIALIZATION ====================
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-that-should-be-long-and-random';

// ==================== NODEMAILER TRANSPORTER ====================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_ADDRESS || 'vk5457396@gmail.com',
    pass: process.env.EMAIL_PASSWORD || 'cnqw jvtq klsa nwtl'
  }
});

// Verify transporter connection
transporter.verify((error, success) => {
  if (error) {
    console.log('✗ Email Service Error:', error);
  } else {
    console.log('✓ Email Service Ready');
  }
});

// ==================== OTP STORAGE (In-Memory) ====================
// Store: { email: { otp: '123456', timestamp: Date, attempts: 0 } }
const otpStorage = new Map();
const OTP_EXPIRY_TIME = 10 * 60 * 1000; // 10 minutes
const MAX_OTP_ATTEMPTS = 5; // Max verification attempts

// Function to clean expired OTPs (run every 5 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of otpStorage.entries()) {
    if (now - data.timestamp > OTP_EXPIRY_TIME) {
      otpStorage.delete(email);
      console.log(`✓ Expired OTP removed for ${email}`);
    }
  }
}, 5 * 60 * 1000);

// ==================== CORS CONFIGURATION ====================
app.use(express.json());

// allow the list to be overridden from environment (comma separated)
const defaultOrigins = [
  'https://noteshare-y2kp.onrender.com',
  'https://note-share-yfyr.onrender.com',
  'http://localhost:5000',
  'http://127.0.0.1:5000',
  'http://localhost:5500',
  'http://127.0.0.1:5500'
];
const envOrigins = process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',').map(o => o.trim()) : null;
const corsOptions = {
  origin: envOrigins || defaultOrigins,
  credentials: true,
  optionsSuccessStatus: 204,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// Explicitly handle preflight across all routes (Express 5 safe)
const allowedOrigins = new Set(corsOptions.origin);
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    const origin = req.headers.origin;
    if (origin && allowedOrigins.has(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Vary', 'Origin');
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Methods', corsOptions.methods.join(','));
      res.header('Access-Control-Allow-Headers', corsOptions.allowedHeaders.join(', '));
      return res.sendStatus(corsOptions.optionsSuccessStatus || 204);
    }
  }
  next();
});
// ==================== MONGODB CONNECTION ====================
const connectionString = process.env.MONGODB_URI || 'mongodb://localhost:27017/noteshare';
const connectionOptions = {
  serverSelectionTimeoutMS: 5000
};
mongoose.connect(connectionString, connectionOptions)
  .then(() => console.log('✓ MongoDB connection successful'))
  .catch(err => {
    console.error('✗ CRITICAL MongoDB Connection Error:', err);
  });
// ==================== MODELS ====================
const User = require('./models/user');
const Note = require('./models/note');
const Feedback = require('./models/feedback');
// ==================== MULTER CONFIGURATION ====================
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });
const avatarStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = path.join(__dirname, 'uploads', 'avatars');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname) || '.png';
    cb(null, Date.now() + ext);
  }
});
const avatarUpload = multer({ storage: avatarStorage });
// ==================== MIDDLEWARE ====================
const protect = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided.' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token.' });
  }
};
const checkRole = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ message: 'Not authenticated.' });
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Insufficient permissions.' });
  }
  next();
};
// ==================== STATIC FILES ====================
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/assetes', express.static(path.join(__dirname, 'assetes')));
// ==================== AUTHENTICATION APIS ====================

// ==================== EMAIL VERIFICATION OTP ====================
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    let { email } = req.body;

    // Normalize email
    email = email?.trim().toLowerCase();

    // Validate email
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required.' 
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid email format.' 
      });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Email content
    const mailOptions = {
      from: process.env.EMAIL_ADDRESS || 'vk5457396@gmail.com',
      to: email,
      subject: 'NoteShare - Email Verification OTP',
      html: `
        <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9; border-radius: 8px;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 8px 8px 0 0; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 28px;">NoteShare</h1>
            <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0;">Email Verification</p>
          </div>
          
          <div style="padding: 30px; background-color: white;">
            <p style="color: #333; font-size: 16px; margin-bottom: 20px;">Hello,</p>
            
            <p style="color: #666; font-size: 14px; line-height: 1.6; margin-bottom: 25px;">
              Thank you for registering with NoteShare. To complete your email verification, please use the following One-Time Password (OTP):
            </p>
            
            <div style="background-color: #f0f2f5; border-left: 4px solid #667eea; padding: 20px; margin: 25px 0; border-radius: 4px;">
              <p style="color: #333; font-size: 12px; margin: 0 0 10px 0; text-transform: uppercase; letter-spacing: 1px;">Your OTP:</p>
              <p style="color: #667eea; font-size: 36px; font-weight: bold; letter-spacing: 5px; margin: 0; text-align: center;">${otp}</p>
            </div>
            
            <p style="color: #e74c3c; font-size: 13px; margin: 20px 0; text-align: center;">
              ⚠️ This OTP is valid for 10 minutes only. Do not share with anyone.
            </p>
            
            <p style="color: #666; font-size: 14px; line-height: 1.6; margin-top: 25px;">
              If you didn't request this OTP, please ignore this email or contact our support team.
            </p>
            
            <hr style="border: none; border-top: 1px solid #eee; margin: 25px 0;">
            
            <p style="color: #999; font-size: 12px; text-align: center; margin: 20px 0 0 0;">
              © 2025 NoteShare. All rights reserved.<br>
              <a href="https://noteshare.com" style="color: #667eea; text-decoration: none;">Visit Website</a>
            </p>
          </div>
        </div>
      `
    };

    // Send email
    await transporter.sendMail(mailOptions);

    // Store OTP in memory with timestamp (for 10 minutes)
    otpStorage.set(email, {
      otp: otp,
      timestamp: Date.now(),
      attempts: 0
    });

    console.log(`✓ OTP sent to ${email} (stored securely, expires in 10 minutes)`);

    // Return success response WITHOUT sending OTP in response (secure!)
    res.status(200).json({
      success: true,
      message: 'OTP sent successfully to your email. Check your inbox.',
      expiresIn: '10 minutes'
      // NOTE: OTP is NOT sent back in response for security!
    });

  } catch (error) {
    console.error('OTP Send Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send OTP. Please try again later.',
      error: error.message 
    });
  }
});

// ==================== VERIFY OTP ENDPOINT ====================
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    let { email, otp } = req.body;

    // Trim and normalize inputs
    email = email?.trim().toLowerCase();
    otp = otp?.trim();

    console.log('📧 Verify OTP Request received:', { email, otp, timestamp: new Date().toISOString() });

    // Validate input
    if (!email || !otp) {
      console.log('❌ Missing email or OTP:', { email: !!email, otp: !!otp });
      return res.status(400).json({
        success: false,
        message: 'Email and OTP are required.'
      });
    }

    // Check if OTP exists for this email
    const otpData = otpStorage.get(email);
    
    console.log('🔍 OTP Storage check:', { email, exists: !!otpData, storedOTP: otpData?.otp, providedOTP: otp });

    if (!otpData) {
      console.log('❌ No OTP found for email:', email);
      return res.status(400).json({
        success: false,
        message: '❌ No OTP found. Please request a new OTP.'
      });
    }

    // Check if OTP has expired (10 minutes)
    const now = Date.now();
    if (now - otpData.timestamp > OTP_EXPIRY_TIME) {
      otpStorage.delete(email);
      return res.status(400).json({
        success: false,
        message: '⏰ OTP has expired. Request a new one.'
      });
    }

    // Check if too many attempts
    if (otpData.attempts >= MAX_OTP_ATTEMPTS) {
      otpStorage.delete(email);
      return res.status(400).json({
        success: false,
        message: '🔒 Too many incorrect attempts. Request a new OTP.'
      });
    }

    // Verify OTP
    if (otpData.otp !== otp) {
      otpData.attempts += 1;
      const remaining = MAX_OTP_ATTEMPTS - otpData.attempts;
      
      if (remaining === 0) {
        otpStorage.delete(email);
        return res.status(400).json({
          success: false,
          message: '🔒 All attempts used. Request a new OTP.'
        });
      }

      return res.status(400).json({
        success: false,
        message: `❌ Invalid OTP. ${remaining} attempts remaining.`,
        attemptsRemaining: remaining
      });
    }

    // OTP is correct! Mark as verified and delete from storage
    otpStorage.delete(email);

    console.log(`✓ OTP verified successfully for ${email}`);

    res.status(200).json({
      success: true,
      message: '✅ Email verified successfully!',
      verified: true
    });

  } catch (error) {
    console.error('OTP Verification Error:', error);
    res.status(500).json({
      success: false,
      message: 'Error verifying OTP. Please try again.',
      error: error.message
    });
  }
});

// ==================== AUTHENTICATION ROUTES ====================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, branch, semester, college, passingYear, secretCode } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Name, email and password are required.' });
    }
    let role = 'student';
    if (secretCode === 'ADMIN_SECRET_CODE_123') {
      role = 'admin';
    } else if (secretCode === 'TEACHER_SECRET_CODE_456') {
      role = 'teacher';
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      branch,
      semester,
      college,
      passingYear,
      role,
      profileImage: ''
    });
    await newUser.save();
    res.status(201).json({
      message: `User registered successfully as ${role}!`,
      user: {
        _id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        branch: newUser.branch,
        semester: newUser.semester,
        college: newUser.college,
        passingYear: newUser.passingYear,
        role: newUser.role,
        isBlocked: newUser.isBlocked,
        profileImage: newUser.profileImage || ''
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error during registration.', error: error.message });
  }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found.' });
    }
    if (user.isBlocked) {
      return res.status(403).json({ message: 'Your account is blocked.' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid password.' });
    }
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        branch: user.branch,
        role: user.role,
        semester: user.semester,
        college: user.college,
        passingYear: user.passingYear,
        isBlocked: user.isBlocked,
        profileImage: user.profileImage || ''
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error during login.', error: error.message });
  }
});
// ==================== NOTE UPLOAD API ====================
app.post('/api/upload', protect, upload.single('note-file'), async (req, res) => {
  try {
    console.log('Received file:', req.file);
    console.log('Received body:', req.body);
    if (!req.file) {
      return res.status(400).json({ message: 'No file was uploaded. Make sure the input name is "note-file".' });
    }
    const allowedExt = ['.pdf'];
    const uploadedExt = path.extname(req.file.originalname || '').toLowerCase();
    if (!allowedExt.includes(uploadedExt)) {
      return res.status(400).json({ message: 'Invalid file type. Only PDF is allowed.' });
    }
    const { title, subject, branch, year, semester, tags } = req.body;
    if (!title || !subject || !branch || !year || !semester) {
      return res.status(400).json({ message: 'Missing required fields: title, subject, branch, year, or semester.' });
    }
    if (!req.user) {
      return res.status(401).json({ message: 'Not authenticated. Missing user information.' });
    }
    const uploader = req.user.userId;
    const newNote = new Note({
      title,
      subject,
      branch,
      year,
      semester,
      tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
      filePath: req.file.path,
      status: 'pending',
      uploader: uploader
    });
    await newNote.save();
    console.log('Note saved successfully to database.');
    res.status(201).json({ message: 'Note uploaded successfully!', note: newNote });
  } catch (err) {
    console.error('!!! SERVER CRASH IN /api/upload !!!');
    console.error(err);
    res.status(500).json({ message: 'A critical error occurred on the server.', error: err.message });
  }
});

// ==================== PDF DOWNLOAD WITH WATERMARK ====================
/**
 * GET /api/download/:filename
 * Downloads PDF with footer containing:
 * - Website name (NoteShare)
 * - Downloaded by: User Name
 * - Download timestamp
 */
app.get('/api/download/:filename', protect, async (req, res) => {
  try {
    // Decode URL-encoded filename
    const filename = decodeURIComponent(req.params.filename);

    // ===== SECURITY VALIDATION =====
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      return res.status(400).json({ message: 'Invalid filename format.' });
    }

    const ext = path.extname(filename).toLowerCase();
    if (ext !== '.pdf') {
      return res.status(400).json({ message: 'Only PDF files can be downloaded.' });
    }

    // ===== FILE PATH CONSTRUCTION =====
    const filePath = path.join(__dirname, 'uploads', filename);

    if (!fs.existsSync(filePath)) {
      console.warn(`⚠️  File not found: ${filename}`);
      return res.status(404).json({ message: 'File not found.' });
    }

    // ===== GET USER INFO =====
    const userId = req.user.userId;
    const user = await User.findById(userId);
    const userName = user ? user.name : 'Unknown User';

    // ===== READ PDF BUFFER =====
    const pdfBuffer = fs.readFileSync(filePath);

    // ===== LOAD PDF WITH pdf-lib =====
    const pdfDoc = await PDFDocument.load(pdfBuffer);
    const pages = pdfDoc.getPages();

    // ===== ADD FOOTER TO EACH PAGE =====
    const currentDate = new Date();
    const dateString = currentDate.toLocaleDateString('en-IN');
    const timeString = currentDate.toLocaleTimeString('en-IN');
    
    pages.forEach((page, index) => {
      const { width, height } = page.getSize();

      // Footer positioning (multi-line at bottom of page)
      const footerStartY = 50; // Starting Y position from bottom
      const footerSize = 9;
      const lineHeight = 12; // Space between lines

      // Line 1: Website name and copyright
      page.drawText('Downloaded from NoteShare (BBSBEC) - © 2025', {
        x: 40,
        y: footerStartY,
        size: footerSize,
        color: rgb(0.3, 0.3, 0.3), // Dark grey
        opacity: 0.7
      });

      // Line 2: Downloaded by user name
      page.drawText(`Downloaded by: ${userName}`, {
        x: 40,
        y: footerStartY - lineHeight,
        size: footerSize,
        color: rgb(0.3, 0.3, 0.3),
        opacity: 0.7
      });

      // Line 3: Date and time (right side)
      page.drawText(`${dateString} | ${timeString}`, {
        x: width - 200,
        y: footerStartY,
        size: footerSize,
        color: rgb(0.5, 0.5, 0.5),
        opacity: 0.6
      });

      // Line 4: Page number (right side)
      page.drawText(`Page ${index + 1}`, {
        x: width - 50,
        y: footerStartY - lineHeight,
        size: footerSize,
        color: rgb(0.5, 0.5, 0.5),
        opacity: 0.5
      });
    });

    // ===== SAVE MODIFIED PDF TO BUFFER =====
    const watermarkedPdf = await pdfDoc.save();

    // ===== SET RESPONSE HEADERS FOR DOWNLOAD =====
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', watermarkedPdf.length);

    // ===== SEND PDF TO CLIENT =====
    res.send(Buffer.from(watermarkedPdf));

    console.log(`✓ PDF downloaded by ${userName}: ${filename}`);
  } catch (err) {
    console.error('❌ PDF Download Error:', err.message);
    res.status(500).json({ message: 'Failed to process PDF download.', error: err.message });
  }
});

// ==================== USER NOTES APIS ====================
app.get('/api/user/notes', protect, async (req, res) => {
  try {
    const userId = req.user && req.user.userId ? req.user.userId : null;
    if (!userId) return res.status(401).json({ message: 'Not authenticated.' });
    const notes = await Note.find({ uploader: userId }).sort({ createdAt: -1 });
    res.json(notes);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch your notes.' });
  }
});
app.get('/api/user/saved-notes/me', protect, async (req, res) => {
  try {
    const userId = req.user && req.user.userId;
    if (!userId) return res.status(401).json({ message: 'Not authenticated.' });
    const user = await User.findById(userId).populate({ path: 'savedNotes', model: 'Note' });
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json(user.savedNotes || []);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch saved notes.' });
  }
});
app.post('/api/user/save-note', protect, async (req, res) => {
  try {
    console.log('=== SAVE NOTE REQUEST ===');
    console.log('req.user:', req.user);
    console.log('req.body:', req.body);
    
    // Get userId - check both _id and userId fields
    const userId = req.user._id || req.user.userId;
    const { noteId } = req.body || {};
    
    console.log('Extracted userId:', userId);
    console.log('Extracted noteId:', noteId);
    
    if (!userId || !noteId) {
      console.log('Missing userId or noteId:', { userId, noteId });
      return res.status(400).json({ message: 'Missing userId or noteId.' });
    }
    
    // Use updateOne to avoid validation issues with existing records
    const result = await User.updateOne(
      { _id: userId },
      { 
        $addToSet: { savedNotes: noteId }
      }
    );
    
    if (result.matchedCount === 0) {
      console.log('User not found:', userId);
      return res.status(404).json({ message: 'User not found.' });
    }
    
    console.log(`✓ Note ${noteId} saved for user ${userId}`);
    return res.json({ message: 'Note saved successfully.' });
  } catch (err) {
    console.error('ERROR in save-note:', err);
    return res.status(500).json({ message: 'Failed to save note.', error: err.message });
  }
});
// ==================== USER PROFILE APIS ====================
app.get('/api/user/saved-notes', async (req, res) => {
  try {
    const userId = req.query.userId;
    if (!userId) return res.status(400).json({ message: 'Missing userId.' });
    const user = await User.findById(userId).populate({
      path: 'savedNotes',
      model: 'Note'
    });
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json(user.savedNotes || []);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch saved notes.' });
  }
});
app.put('/api/profile', protect, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { name, branch, semester, college, passingYear } = req.body;
    const updateFields = {};
    if (name) updateFields.name = name;
    if (branch) updateFields.branch = branch;
    if (semester) updateFields.semester = semester;
    if (college) updateFields.college = college;
    if (passingYear) updateFields.passingYear = passingYear;
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: updateFields },
      { new: true }
    );
    res.json({ message: 'Profile updated successfully!', user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: 'Error updating profile.', error: error.message });
  }
});
app.post('/api/user/avatar', protect, avatarUpload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
    const userId = req.user && req.user.userId;
    if (!userId) return res.status(401).json({ message: 'Not authenticated.' });
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    if (user.profileImage) {
      const prev = path.join(__dirname, user.profileImage);
      fs.unlink(prev, (err) => { if (err) {/* ignore */ } });
    }
    const relPath = path.join('uploads', 'avatars', path.basename(req.file.path)).replace(/\\/g, '/');
    user.profileImage = relPath;
    await user.save();
    res.json({ message: 'Avatar uploaded.', profileImage: user.profileImage });
  } catch (err) {
    res.status(500).json({ message: 'Avatar upload failed.', error: err.message });
  }
});
// ==================== PUBLIC NOTES API ====================
app.get('/api/notes', async (req, res) => {
  try {
    const { search = '', branch = '' } = req.query;
    let filter = { status: 'accepted' };
    if (branch) {
      filter.branch = { $regex: `^${branch}$`, $options: 'i' };
    }
    let notes = await Note.find(filter).sort({ createdAt: -1 });
    if (search) {
      const q = search.toLowerCase();
      notes = notes.filter(note =>
        (note.title && note.title.toLowerCase().includes(q)) ||
        (note.subject && note.subject.toLowerCase().includes(q)) ||
        (note.branch && note.branch.toLowerCase().includes(q)) ||
        (String(note.year).toLowerCase().includes(q)) ||
        (String(note.semester).toLowerCase().includes(q))
      );
    }
    res.json(notes);
  } catch (err) {
    console.error('Error fetching notes:', err);
    res.status(500).json({ message: 'Failed to fetch notes from the database.' });
  }
});
// ==================== ADMIN APIS ====================
app.get('/api/admin/users', protect, checkRole('admin'), async (req, res) => {
  try {
    const users = await User.find({});
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching users.', error: err.message });
  }
});
app.post('/api/admin/users/:id/block', protect, checkRole('admin'), async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.id, { isBlocked: true });
    res.json({ message: 'User blocked successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Error blocking user.', error: err.message });
  }
});
app.post('/api/admin/users/:id/unblock', protect, checkRole('admin'), async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.id, { isBlocked: false });
    res.json({ message: 'User unblocked successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Error unblocking user.', error: err.message });
  }
});
app.put('/api/admin/user/:id/role', protect, checkRole('admin'), async (req, res) => {
  try {
    const { role } = req.body;
    if (!role) return res.status(400).json({ message: 'Role is required.' });
    const allowed = ['student', 'teacher', 'admin'];
    if (!allowed.includes(role)) return res.status(400).json({ message: 'Invalid role.' });
    const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({ message: 'Role updated.', user });
  } catch (err) {
    res.status(500).json({ message: 'Error updating role.', error: err.message });
  }
});
app.get('/api/admin/notes', protect, checkRole('admin', 'teacher'), async (req, res) => {
  try {
    const notes = await Note.find().sort({ createdAt: -1 });
    res.json(notes);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching notes.', error: err.message });
  }
});
app.post('/api/admin/notes/:id/accept', protect, checkRole('admin', 'teacher'), async (req, res) => {
  try {
    const note = await Note.findByIdAndUpdate(req.params.id, { status: 'accepted' }, { new: true });
    if (!note) return res.status(404).json({ message: 'Note not found.' });
    res.json({ message: 'Note accepted successfully.', note });
  } catch (err) {
    res.status(500).json({ message: 'Error accepting note.', error: err.message });
  }
});
app.post('/api/admin/notes/:id/reject', protect, checkRole('admin', 'teacher'), async (req, res) => {
  try {
    const note = await Note.findByIdAndUpdate(req.params.id, { status: 'rejected' }, { new: true });
    if (!note) return res.status(404).json({ message: 'Note not found.' });
    res.json({ message: 'Note rejected successfully.', note });
  } catch (err) {
    res.status(500).json({ message: 'Error rejecting note.', error: err.message });
  }
});
app.delete('/api/admin/notes/:id', protect, checkRole('admin', 'teacher'), async (req, res) => {
  try {
    const note = await Note.findById(req.params.id);
    if (!note) {
      return res.status(404).json({ message: 'Note not found.' });
    }
    fs.unlink(note.filePath, (err) => {
      if (err) console.error('Error deleting file:', err);
    });
    await Note.findByIdAndDelete(req.params.id);
    res.json({ message: 'Note deleted successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting note.', error: err.message });
  }
});
app.put('/api/admin/notes/:id', protect, checkRole('admin', 'teacher'), async (req, res) => {
  try {
    const allowed = ['title', 'subject', 'branch', 'year', 'semester', 'tags', 'status'];
    const updates = {};
    for (const key of Object.keys(req.body)) {
      if (allowed.includes(key)) updates[key] = req.body[key];
    }
    if (Object.keys(updates).length === 0) return res.status(400).json({ message: 'No valid fields to update.' });
    const note = await Note.findByIdAndUpdate(req.params.id, { $set: updates }, { new: true });
    if (!note) return res.status(404).json({ message: 'Note not found.' });
    res.json({ message: 'Note updated.', note });
  } catch (err) {
    res.status(500).json({ message: 'Error updating note.', error: err.message });
  }
});
app.get('/api/admin/metrics', protect, checkRole('admin'), async (req, res) => {
  try {
    const totalNotes = await Note.countDocuments();
    const pendingNotes = await Note.countDocuments({ status: 'pending' });
    const acceptedNotes = await Note.countDocuments({ status: 'accepted' });
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const recentUploads = await Note.find({ createdAt: { $gte: sevenDaysAgo } }).sort({ createdAt: -1 }).limit(20);
    const branches = await Note.aggregate([
      { $group: { _id: { $ifNull: ['$branch', 'Unknown'] }, count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    res.json({ totalNotes, pendingNotes, acceptedNotes, recentUploads, topBranches: branches });
  } catch (err) {
    res.status(500).json({ message: 'Error fetching metrics.', error: err.message });
  }
});
app.get('/api/admin/feedback', protect, checkRole('admin'), async (req, res) => {
  try {
    const items = await Feedback.find().sort({ createdAt: -1 }).limit(200);
    res.json(items);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch feedback.', error: err.message });
  }
});
// ==================== FEEDBACK API ====================

// ... (existing code)

// ==================== FEEDBACK API ====================
app.post('/api/feedback', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    if (!name || !email || !message) return res.status(400).json({ message: 'All fields are required.' });

    // Save to DB
    const fb = new Feedback({ name, email, message });
    await fb.save();

    // Send Email using Nodemailer
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'vk5457396@gmail.com',
        pass: 'cnqwjvtqklsanwtl' // App Password (spaces removed)
      }
    });

    const mailOptions = {
      from: '"College NoteShare" <vk5457396@gmail.com>', // Always send from authenticated address
      replyTo: email, // Allow replying to the user
      to: 'vk5457396@gmail.com', // List of receivers
      subject: `New Feedback from ${name} - College NoteShare`, // Subject line
      text: `Name: ${name}\nEmail: ${email}\n\nMessage:\n${message}`, // Plain text body
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
          <h2 style="color: #4F46E5;">New Feedback Received</h2>
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Email:</strong> ${email}</p>
          <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
          <p><strong>Message:</strong></p>
          <p style="background: #f9f9f9; padding: 15px; border-radius: 5px; color: #333;">${message}</p>
        </div>
      ` // HTML body
    };

    await transporter.sendMail(mailOptions);
    console.log('Feedback email sent successfully.');

    res.status(201).json({ message: 'Thank you! Your feedback has been sent.' });
  } catch (err) {
    console.error('Feedback Error:', err);
    res.status(500).json({ message: 'Failed to save feedback.', error: err.message });
  }
});
// ==================== SERVER STARTUP & DEFAULTS ====================
const ensureDefaultUsers = async () => {
  try {
    const adminEmail = 'admin@noteshare.com';
    const adminPass = 'admin123';
    const admin = await User.findOne({ email: adminEmail, role: 'admin' });
    if (!admin) {
      const hashed = await bcrypt.hash(adminPass, 10);
      await User.create({
        name: 'Admin',
        email: adminEmail,
        password: hashed,
        role: 'admin',
        semester: '',
        college: '',
        passingYear: ''
      });
      console.log('✓ Default admin user created: admin@noteshare.com / admin123');
    } else {
      console.log('✓ Default admin user already exists.');
    }
    const teacherEmail = 'teacher@noteshare.com';
    const teacherPass = 'teacher123';
    const teacher = await User.findOne({ email: teacherEmail, role: 'teacher' });
    if (!teacher) {
      const hashed = await bcrypt.hash(teacherPass, 10);
      await User.create({
        name: 'Teacher',
        email: teacherEmail,
        password: hashed,
        role: 'teacher',
        semester: '',
        college: '',
        passingYear: ''
      });
      console.log('✓ Default teacher user created: teacher@noteshare.com / teacher123');
    } else {
      console.log('✓ Default teacher user already exists.');
    }
  } catch (err) {
    console.error('Error creating default users:', err);
  }
};
// ==================== NOTES BY BRANCH ====================
app.get('/api/notes', async (req, res) => {
  try {
    const { branch } = req.query;
    if (!branch) {
      return res.status(400).json({ message: 'Branch parameter is required' });
    }

    const notes = await Note.find({ branch })
      .populate('uploadedBy', 'name email')
      .sort({ createdAt: -1 });

    res.json(notes);
  } catch (err) {
    console.error('Error fetching notes by branch:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// ==================== LEADERBOARD API ====================
app.get('/api/leaderboard', async (req, res) => {
  try {
    const leaderboard = await Note.aggregate([
      { $match: { status: 'accepted' } },
      { $group: { _id: '$uploader', totalUploads: { $sum: 1 } } },
      { $sort: { totalUploads: -1 } },
      { $limit: 5 },
      { $lookup: { from: 'users', localField: '_id', foreignField: '_id', as: 'userDetails' } },
      { $unwind: '$userDetails' },
      { $project: {
        userId: '$_id',
        name: '$userDetails.name',
        avatar: '$userDetails.profileImage',
        totalUploads: 1,
        branch: '$userDetails.branch',
        _id: 0
      }}
    ]);

    const rankedLeaderboard = leaderboard.map((entry, index) => ({
      rank: index + 1,
      ...entry
    }));

    res.json({ success: true, data: rankedLeaderboard });
  } catch (err) {
    console.error('Error fetching leaderboard:', err);
    res.status(500).json({ success: false, message: 'Error fetching leaderboard', error: err.message });
  }
});

// ==================== USER STATS ENDPOINT ====================
app.get('/api/user/stats/:userId', protect, async (req, res) => {
  try {
    const { userId } = req.params;
    console.log('\n📊 FETCHING STATS FOR USER:', userId);

    // Find all notes uploaded by this user (using 'uploader' field)
    const notes = await Note.find({ uploader: userId });
    
    const notesCount = notes.length;
    console.log('📝 Total notes found:', notesCount);
    
    let totalDownloads = 0;
    let totalRatings = 0;
    let ratingSum = 0;

    // Calculate stats from all user's notes
    notes.forEach(note => {
      totalDownloads += note.downloads || 0;
      if (note.ratings && note.ratings.length > 0) {
        totalRatings += note.ratings.length;
        const sum = note.ratings.reduce((acc, r) => acc + (r.rating || 0), 0);
        ratingSum += sum;
      }
    });

    const averageRating = totalRatings > 0 ? ratingSum / totalRatings : 0;
    
    // Check eligibility for certificate (minimum 20 notes)
    const eligibleForCertificate = notesCount >= 20;
    
    console.log('✅ Eligible for certificate:', eligibleForCertificate);
    console.log('📊 Notes count:', notesCount, '(Need: >= 20)');

    const stats = {
      success: true,
      notesCount,
      downloadsCount: totalDownloads,
      totalRatings,
      averageRating: averageRating.toFixed(2),
      eligibleForCertificate,
      certificateRequirement: 20,
      notesRemaining: Math.max(0, 20 - notesCount)
    };

    console.log('✓ Stats Response:', stats);
    res.json(stats);
  } catch (error) {
    console.error('❌ Error fetching user stats:', error);
    res.status(500).json({ success: false, message: 'Error fetching stats', error: error.message });
  }
});

// ==================== API 404 & ERROR HANDLER ====================
app.use('/api', (req, res, next) => {
  res.status(404).json({ message: 'API endpoint not found.' });
});
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);
  if (req.path && req.path.startsWith('/api')) {
    return res.status(500).json({ message: 'Internal server error.', error: err.message });
  }
  next(err);
});
// ==================== SERVER LISTEN ====================
app.listen(PORT, async () => {
  await ensureDefaultUsers();
  console.log(`\n╔════════════════════════════════════════╗`);
  console.log(`║  🚀 Server running on port ${PORT}        ║`);
  console.log(`║  📊 Environment: ${process.env.NODE_ENV || 'production'}          ║`);
  console.log(`║  🌍 CORS Enabled for Render & localhost ║`);
  console.log(`╚════════════════════════════════════════╝\n`);
});
module.exports = app;

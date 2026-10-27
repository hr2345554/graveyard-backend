import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import nodemailer from 'nodemailer';
import cookieParser from 'cookie-parser'; // 🌟 COOKIE PARSER

dotenv.config();

const app = express();

// Vercel Proxy ke liye zaroori hai (Rate limit error fix)
app.set('trust proxy', 1);

// ==========================================
// 1. CORS
// ==========================================
app.use(cors({
  origin: [
    'http://localhost:3000', 
    'http://localhost:5173', 
    'http://127.0.0.1:3000', 
    'http://127.0.0.1:5173',
    'https://subscription-graveyard-five.vercel.app' // Aapki live site
  ],
  credentials: true, // 🌟 Cookies allow karne ke liye
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.options('*', cors());

// ==========================================
// 2. SECURITY MIDDLEWARES
// ==========================================
app.use(helmet({
  crossOriginResourcePolicy: false
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 10000, 
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true, 
  legacyHeaders: false, 
});
app.use('/api', limiter);

app.use(mongoSanitize());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser()); // 🌟 COOKIE PARSER MIDDLEWARE

// ==========================================
// 3. DATABASE CONNECTION (Vercel Serverless Fix)
// ==========================================
let cached = global.mongoose;

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
  if (cached.conn) return cached.conn;

  if (!cached.promise) {
    const opts = { bufferCommands: false };
    cached.promise = mongoose.connect(process.env.MONGO_URI, opts).then((mongoose) => {
      console.log('✅ MongoDB Connected Successfully');
      return mongoose;
    });
  }
  
  try {
    cached.conn = await cached.promise;
  } catch (e) {
    cached.promise = null;
    console.error('❌ MongoDB connection error:', e);
    throw e;
  }

  return cached.conn;
}

app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (error) {
    res.status(500).json({ message: 'Database connection failed. Check MONGO_URI in Vercel.' });
  }
});

// ==========================================
// 4. DATABASE MODELS
// ==========================================
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetCode: { type: String, default: null },
  resetCodeExpires: { type: Date, default: null }
}, { timestamps: true });

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);

const subscriptionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
  name: { type: String, required: true },
  price: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  billingFrequency: { type: String, enum: ['weekly', 'monthly', 'quarterly', 'yearly'], required: true },
  category: { type: String, required: true },
  status: { type: String, enum: ['active', 'cancelled', 'paused'], default: 'active' },
  websiteUrl: { type: String, default: '' },
  startDate: { type: Date },
  renewalDate: { type: Date },
  notes: { type: String, default: '' },
  cancellationDate: { type: Date },
  cancellationReason: { type: String, default: '' },
  
  isWorthIt: { type: Boolean, default: null },
  lastRatedDate: { type: Date },
  isShared: { type: Boolean, default: false },
  sharedWith: [{
    email: { type: String, required: true },
    amountOwed: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'accepted'], default: 'pending' }, 
    hasPaid: { type: Boolean, default: false }
  }]
}, { timestamps: true });

// 🌟 NAYA: Search + Status filter ko fast karne ke liye Database Index
subscriptionSchema.index({ user: 1, name: 1, status: 1 });

const Subscription = mongoose.model('Subscription', subscriptionSchema);

// ==========================================
// 5. AUTH MIDDLEWARE
// ==========================================
const protect = async (req, res, next) => {
  // 🌟 COOKIE SE TOKEN READ KAR RAHE HAIN
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: 'Not authorized, no token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-password');
    next();
  } catch (error) {
    res.status(401).json({ message: 'Not authorized, token failed' });
  }
};

const generateToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '30d' });

// ==========================================
// 6. AUTH ROUTES
// ==========================================
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });
    
    const user = await User.create({ name, email, password });
    const token = generateToken(user._id);

    // 🌟 COOKIE SET KAR RAHE HAIN
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', 
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 din
    });

    res.status(201).json({ _id: user._id, name: user.name, email: user.email });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ 
        message: 'This email is not registered. Please sign up first.', 
        code: 'EMAIL_NOT_FOUND' 
      });
    }

    if (await user.matchPassword(password)) {
      const token = generateToken(user._id);

      // 🌟 COOKIE SET KAR RAHE HAIN
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 din
      });

      res.json({ _id: user._id, name: user.name, email: user.email });
    } else {
      res.status(401).json({ message: 'Invalid password. Please try again.' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// 🌟 LOGOUT ROUTE (Cookie Clear karne ke liye)
app.post('/api/auth/logout', (req, res) => {
  res.cookie('token', '', {
    httpOnly: true,
    expires: new Date(0),
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  });
  res.json({ message: 'Logged out successfully' });
});

// 🌟 User ko Search karna (Split Modal ke liye)
app.get('/api/auth/search', protect, async (req, res) => {
  try {
    const query = req.query.q;
    if (!query) return res.json([]);

    const users = await User.find({
      $or: [
        { name: { $regex: query, $options: 'i' } },
        { email: { $regex: query, $options: 'i' } }
      ],
      _id: { $ne: req.user._id }
    }).select('_id name email').limit(5);

    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ==========================================
// 7. NODEMAILER & PASSWORD RESET ROUTES
// ==========================================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Yeh email registered nahi hai.' });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetCode = code;
    user.resetCodeExpires = Date.now() + 10 * 60 * 1000;
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Code - Subscription Graveyard',
      html: `
        <div style="font-family: Arial; padding: 20px; text-align: center;">
          <h2>Password Reset</h2>
          <p>Aapka password reset code yeh hai:</p>
          <h1 style="color: #7C3AED; font-size: 40px; letter-spacing: 5px;">${code}</h1>
          <p>Yeh code 10 minute ke liye valid hai.</p>
        </div>
      `
    });

    res.json({ message: 'Code email par bhej diya gaya hai.' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User nahi mila.' });
    if (user.resetCode !== code) return res.status(400).json({ message: 'Ghalat code dala hai.' });
    if (user.resetCodeExpires < Date.now()) return res.status(400).json({ message: 'Code expire ho gaya hai.' });

    user.password = newPassword;
    user.resetCode = null;
    user.resetCodeExpires = null;
    await user.save();

    res.json({ message: 'Password successfully change ho gaya!' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.delete('/api/auth/delete-account', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    await Subscription.deleteMany({ user: userId });
    await User.findByIdAndDelete(userId);
    res.json({ message: 'Account and all associated data deleted successfully.' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ==========================================
// 8. SUBSCRIPTION ROUTES (Updated: Search + Status + Pagination)
// ==========================================
app.get('/api/subscriptions', protect, async (req, res) => {
  try {
    // 🌟 Query params read karo
    const page   = parseInt(req.query.page) || 1;
    const limit  = parseInt(req.query.limit) || 10;
    const search = req.query.search || '';
    const status = req.query.status || 'active';

    // Base query — sirf apne subscriptions
    const query = { user: req.user._id };

    // 🌟 Status filter (active / cancelled / paused / all)
    if (status !== 'all') {
      query.status = status;
    }

    // 🌟 Search filter (name + category dono pe)
    if (search) {
      query.$or = [
        { name:     { $regex: search, $options: 'i' } },
        { category: { $regex: search, $options: 'i' } },
      ];
    }

    // Total count (pagination ke liye)
    const total = await Subscription.countDocuments(query);

    // Data fetch (skip + limit)
    const subs = await Subscription.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    res.json({
      data: subs,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      totalItems: total,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/subscriptions', protect, async (req, res) => {
  try {
    const sub = await Subscription.create({ ...req.body, user: req.user._id });
    res.status(201).json(sub);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.put('/api/subscriptions/:id', protect, async (req, res) => {
  try {
    if (!req.params.id || req.params.id === 'undefined') {
      return res.status(400).json({ message: 'Invalid subscription ID' });
    }
    const sub = await Subscription.findById(req.params.id);
    if (!sub) return res.status(404).json({ message: 'Subscription not found' });
    if (sub.user.toString() !== req.user._id.toString()) return res.status(401).json({ message: 'Not authorized' });
    
    const updatedSub = await Subscription.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updatedSub);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.delete('/api/subscriptions/:id', protect, async (req, res) => {
  try {
    if (!req.params.id || req.params.id === 'undefined') {
      return res.status(400).json({ message: 'Invalid subscription ID' });
    }
    const sub = await Subscription.findById(req.params.id);
    if (!sub) return res.status(404).json({ message: 'Subscription not found' });
    if (sub.user.toString() !== req.user._id.toString()) return res.status(401).json({ message: 'Not authorized' });
    
    await sub.deleteOne();
    res.json({ message: 'Subscription removed' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ==========================================
// 9. WORTH IT & SPLIT ROUTES (OWNER)
// ==========================================
app.patch('/api/subscriptions/:id/rate', protect, async (req, res) => {
  try {
    const { isWorthIt } = req.body;
    const sub = await Subscription.findById(req.params.id);
    
    if (!sub) return res.status(404).json({ message: 'Subscription not found' });
    if (sub.user.toString() !== req.user._id.toString()) return res.status(401).json({ message: 'Not authorized' });

    const updatedSub = await Subscription.findByIdAndUpdate(
      req.params.id,
      { isWorthIt, lastRatedDate: new Date() },
      { new: true }
    );
    res.json(updatedSub);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.patch('/api/subscriptions/:id/split', protect, async (req, res) => {
  try {
    const { sharedWith } = req.body;
    const sub = await Subscription.findById(req.params.id);
    
    if (!sub) return res.status(404).json({ message: 'Subscription not found' });
    if (sub.user.toString() !== req.user._id.toString()) return res.status(401).json({ message: 'Not authorized' });

    const updatedSub = await Subscription.findByIdAndUpdate(
      req.params.id,
      { 
        sharedWith, 
        isShared: sharedWith && sharedWith.length > 0 
      },
      { new: true }
    );
    res.json(updatedSub);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ==========================================
// 🌟 10. SHARED WITH ME ROUTES (FRIEND KE LIYE)
// ==========================================

app.get('/api/splits/shared-with-me', protect, async (req, res) => {
  try {
    const subs = await Subscription.find({ 'sharedWith.email': req.user.email })
      .populate('user', 'name email'); 
    
    const sharedSplits = [];
    
    subs.forEach(sub => {
      sub.sharedWith.forEach(friend => {
        if (friend.email === req.user.email) {
          sharedSplits.push({
            _id: friend._id,
            subscription: sub,
            owner: sub.user,
            amountOwed: friend.amountOwed,
            status: friend.status,
            hasPaid: friend.hasPaid
          });
        }
      });
    });
    
    res.json(sharedSplits);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.patch('/api/splits/:id/accept', protect, async (req, res) => {
  try {
    const sub = await Subscription.findOne({ 'sharedWith._id': req.params.id });
    if (!sub) return res.status(404).json({ message: 'Split not found' });
    
    const friend = sub.sharedWith.id(req.params.id);
    if (!friend) return res.status(404).json({ message: 'Split not found' });
    
    if (friend.email !== req.user.email) {
      return res.status(401).json({ message: 'Not authorized' });
    }

    friend.status = 'accepted';
    await sub.save();
    
    res.json({ message: 'Accepted successfully', friend });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.patch('/api/splits/:id/pay', protect, async (req, res) => {
  try {
    const sub = await Subscription.findOne({ 'sharedWith._id': req.params.id });
    
    if (!sub) return res.status(404).json({ message: 'Split not found' });

    const friend = sub.sharedWith.id(req.params.id);
    if (!friend) return res.status(404).json({ message: 'Split not found' });
    
    if (friend.email !== req.user.email) {
      return res.status(401).json({ message: 'You are not authorized to pay this.' });
    }

    friend.hasPaid = true;
    await sub.save();
    
    res.json({ message: 'Marked as paid', friend });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.delete('/api/splits/:id', protect, async (req, res) => {
  try {
    const sub = await Subscription.findOne({ 'sharedWith._id': req.params.id });
    if (!sub) return res.status(404).json({ message: 'Split not found' });
    
    const friend = sub.sharedWith.id(req.params.id);
    if (!friend) return res.status(404).json({ message: 'Split not found' });
    
    const isOwner = sub.user.toString() === req.user._id.toString();
    const isFriend = friend.email === req.user.email;

    if (!isOwner && !isFriend) {
      return res.status(401).json({ message: 'Not authorized to remove this.' });
    }

    sub.sharedWith.pull({ _id: req.params.id });
    
    if (sub.sharedWith.length === 0) {
      sub.isShared = false;
    }
    
    await sub.save();
    res.json({ message: 'Removed successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ==========================================
// 11. VERCEL CRON JOB: SPLIT REMINDER EMAILS
// ==========================================
app.get('/api/cron/reminders', async (req, res) => {
  try {
    if (req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) {
       return res.status(401).json({ message: 'Unauthorized' });
    }

    const sharedSubs = await Subscription.find({ isShared: true, status: 'active' });
    let emailsSent = 0;

    for (const sub of sharedSubs) {
      for (const friend of sub.sharedWith) {
        if (friend.status === 'accepted' && !friend.hasPaid) {
          await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: friend.email,
            subject: `Reminder: Your share for ${sub.name}`,
            html: `
              <div style="font-family: Arial; padding: 20px; text-align: center;">
                <h2>Subscription Share Reminder</h2>
                <p>Hi there,</p>
                <p>Your share of <strong>$${friend.amountOwed}</strong> for <strong>${sub.name}</strong> is pending.</p>
                <p>Please contact the account owner to pay.</p>
              </div>
            `
          });
          emailsSent++;
        }
      }
    }
    res.json({ success: true, emailsSent });
  } catch (error) {
    console.error('Cron error:', error);
    res.status(500).json({ message: error.message });
  }
});

// ==========================================
// 12. SERVER START
// ==========================================
app.get('/', (req, res) => res.send('Graveyard API is running securely!'));

export default app;
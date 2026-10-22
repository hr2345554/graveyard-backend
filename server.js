import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';

dotenv.config();

// Yeh sirf ek baar aayega ab
const app = express();

// ==========================================
// SECURITY MIDDLEWARES
// ==========================================
// 1. HTTP Headers secure karna
app.use(helmet());

// 2. Rate Limiting (15 minute mein max 100 requests per IP)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100, 
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api', limiter);

// 3. NoSQL Injection se bachne ke liye
app.use(mongoSanitize());

// 4. CORS (Frontend ko connect hone dena)
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:5173'], // Vite 5173 use karta hai, CRA 3000
  credentials: true
}));

// Body parser (JSON data padhne ke liye)
app.use(express.json({ limit: '10kb' }));


// ==========================================
// 1. DATABASE MODELS
// ==========================================
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
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
  cancellationReason: { type: String, default: '' }
}, { timestamps: true });

const Subscription = mongoose.model('Subscription', subscriptionSchema);


// ==========================================
// 2. AUTH MIDDLEWARE
// ==========================================
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select('-password');
      next();
    } catch (error) {
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  }
  if (!token) {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

const generateToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '30d' });


// ==========================================
// 3. AUTH ROUTES
// ==========================================
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });
    
    const user = await User.create({ name, email, password });
    res.status(201).json({ _id: user._id, name: user.name, email: user.email, token: generateToken(user._id) });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user && (await user.matchPassword(password))) {
      res.json({ _id: user._id, name: user.name, email: user.email, token: generateToken(user._id) });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


// ==========================================
// 4. SUBSCRIPTION ROUTES
// ==========================================
app.get('/api/subscriptions', protect, async (req, res) => {
  try {
    const subs = await Subscription.find({ user: req.user._id }).sort({ createdAt: -1 });
    res.json(subs);
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
// 5. SERVER START & DB CONNECT
// ==========================================
app.get('/', (req, res) => res.send('Graveyard API is running securely!'));

const PORT = process.env.PORT || 5000;

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB Connected Successfully');
    app.listen(PORT, () => console.log(`🚀 Server running securely on port ${PORT}`));
  })
  .catch((err) => console.log('❌ MongoDB connection error:', err));
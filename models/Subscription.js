import mongoose from 'mongoose';

const subscriptionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
  name: { type: String, required: true },
  price: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  billingFrequency: { type: String, enum: ['weekly', 'monthly', 'quarterly', 'yearly'], required: true },
  category: { type: String, required: true },
  status: { type: String, enum: ['active', 'cancelled', 'paused'], default: 'active' },
  
  // Logo fetch karne aur dates save karne ke liye yeh fields zaroori hain
  websiteUrl: { type: String, default: '' },
  startDate: { type: Date },
  renewalDate: { type: Date },
  notes: { type: String, default: '' },
  cancellationDate: { type: Date },
  cancellationReason: { type: String, default: '' }
}, { timestamps: true });

export default mongoose.model('Subscription', subscriptionSchema);
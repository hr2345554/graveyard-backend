const mongoose = require('mongoose');

const splitSchema = new mongoose.Schema({
  subscription: { type: mongoose.Schema.Types.ObjectId, ref: 'Subscription', required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Jisne share kiya
  sharedWith: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Jisko share kiya
  amountOwed: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'paid'], default: 'pending' } // Pay Now ke liye
}, { timestamps: true });

module.exports = mongoose.model('Split', splitSchema);
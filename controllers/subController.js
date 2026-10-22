import Subscription from '../models/Subscription.js';

// Saari subscriptions lana
export const getSubscriptions = async (req, res) => {
  try {
    const subs = await Subscription.find({ user: req.user._id });
    res.json(subs);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Nayi subscription add karna (...req.body se saari fields save ho jayengi)
export const createSubscription = async (req, res) => {
  try {
    const sub = await Subscription.create({ ...req.body, user: req.user._id });
    res.status(201).json(sub);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Update karna (Cancel karne ke liye bhi yehi use hota hai)
export const updateSubscription = async (req, res) => {
  try {
    const sub = await Subscription.findById(req.params.id);
    if (!sub) return res.status(404).json({ message: 'Subscription not found' });
    if (sub.user.toString() !== req.user._id.toString()) return res.status(401).json({ message: 'Not authorized' });

    const updatedSub = await Subscription.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updatedSub);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Permanent delete karna
export const deleteSubscription = async (req, res) => {
  try {
    const sub = await Subscription.findById(req.params.id);
    if (!sub) return res.status(404).json({ message: 'Subscription not found' });
    if (sub.user.toString() !== req.user._id.toString()) return res.status(401).json({ message: 'Not authorized' });
    
    await sub.deleteOne();
    res.json({ message: 'Subscription removed' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
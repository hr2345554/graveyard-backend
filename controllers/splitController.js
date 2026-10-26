const Split = require('../models/Split');

// 1. Jab aap "Send Invite" dabayein (SplitModal se)
exports.createSplit = async (req, res) => {
  try {
    const { subscriptionId, sharedWithUserId, amountOwed } = req.body;
    
    const newSplit = await Split.create({
      subscription: subscriptionId,
      owner: req.user._id, // Logged in user
      sharedWith: sharedWithUserId,
      amountOwed: amountOwed,
      status: 'pending'
    });

    res.status(201).json(newSplit);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// 2. Jab dost apna "Shared with Me" tab khole
exports.getMySharedSplits = async (req, res) => {
  try {
    // Wo saare splits dhoondo jisme dost ko share kiya gaya ho
    const splits = await Split.find({ sharedWith: req.user._id })
      .populate('subscription') // Netflix ki details laao
      .populate('owner', 'name'); // Ali Khan ka naam laao

    res.status(200).json(splits);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// 3. Jab "Pay Now" dabayein
exports.markAsPaid = async (req, res) => {
  try {
    await Split.findByIdAndUpdate(req.params.id, { status: 'paid' });
    res.status(200).json({ message: 'Marked as paid' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
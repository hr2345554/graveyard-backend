const express = require('express');
const router = express.Router();
const { createSplit, getMySharedSplits, markAsPaid } = require('../controllers/splitController');
const { protect } = require('../middleware/authMiddleware'); // Aapka auth middleware

router.post('/', protect, createSplit);
router.get('/shared-with-me', protect, getMySharedSplits);
router.patch('/:id/pay', protect, markAsPaid);

module.exports = router;
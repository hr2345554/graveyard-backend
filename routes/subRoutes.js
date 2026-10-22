import express from 'express';
import { getSubscriptions, createSubscription, updateSubscription, deleteSubscription } from '../controllers/subController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

router.route('/')
  .get(protect, getSubscriptions)
  .post(protect, createSubscription);

router.route('/:id')
  .put(protect, updateSubscription)
  .delete(protect, deleteSubscription);

export default router;
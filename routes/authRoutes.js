import express from 'express';
import { register, login, logout ,requestPasswordReset,resetPassword} from '../controllers/authControllers.js';
import { verifyToken } from '../middleware/auth.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/forgot-password', requestPasswordReset);
router.post('/reset-password', resetPassword);

router.post('/logout', verifyToken, logout);

export default router;

import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import { sendEmail } from '../config/email.js';

export const register = async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.json({
            success: false, message: 'missing details'
        })
    }
    try {
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.json({ success: false, message: "user already exists" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new userModel({ name, email, password: hashedPassword , isOnboarded: false })
        await user.save();
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, {
            httpOnly: true, secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({ success: true});
    } catch (error) {
        res.json({ success: false, message: error.message })
    }
}
export const login = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        res.json({ success: false, message: 'missing details' })
    }
    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: 'password or email is invalid' })
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.json({ success: false, message: 'Invalid passsword or email' })
        }
         user.lastActivityDate = new Date();
        await user.save();
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true, secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({ success: true });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}
export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', path: '/'
        })
        return res.json({
            success: true, message: "logged out"
        })

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}


export const requestPasswordReset = async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ success: false, message: 'Email is required' });

  const user = await userModel.findOne({ email });
  if (!user) return res.json({ success: false, message: 'User not found' });

  // Create reset token
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  // Hash token before saving to DB for security
  user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  user.resetPasswordExpire = Date.now() + 300000; // 5 min expiry
  await user.save();

  // Construct reset URL to be sent via email
  const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

  const message = `You requested a password reset. Please use the following link to reset your password:\n\n${resetUrl}\n\nIf you did not request this, please ignore this email.`;

  try {
    await sendEmail(user.email, 'Password Reset Request', message);
    res.json({ success: true, message: 'Reset email sent' });
  } catch (error) {
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();
    res.json({ success: false, message: 'Email could not be sent' });
  }
};

export const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) 
    return res.json({ success: false, message: 'Token and new password are required' });

  // Hash the token from URL to compare with DB
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  const user = await userModel.findOne({
    resetPasswordToken: hashedToken,
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user) return res.json({ success: false, message: 'Invalid or expired token' });

  // Update password and clear reset token fields
  user.password = await bcrypt.hash(newPassword, 10);
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;
  await user.save();

  res.json({ success: true, message: 'Password updated successfully' });
};

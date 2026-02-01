import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { parsePhoneNumberFromString } from 'libphonenumber-js';

import { users, verificationCodes, sessions, resetTokens, resetAuthStore } from '../store/auth';
import type { User } from '../store/auth';
import { requireAuth, AuthenticatedRequest } from '../middleware/auth';

type RegisterRequest = {
  firstName: string;
  lastName: string;
  email: string;
  phoneNumber: string;
  password: string;
};

type VerifyCodeRequest = {
  verificationId: string;
  code: string;
};

type LoginRequest = {
  email: string;
  password: string;
};

type VerificationStatusRequest = {
  verificationId: string;
};

type ForgotPasswordRequest = {
  email: string;
};

type ResetPasswordRequest = {
  token: string;
  password: string;
  confirmPassword: string;
};

type SetPasswordRequest = {
  password: string;
  confirmPassword: string;
};

type ErrorResponse = {
  error: string;
  field?: string;
};

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const defaultResetTokenTtlMs = 15 * 60 * 1000;
const resetTokenTtlMs = Number(process.env.RESET_TOKEN_TTL_MS ?? defaultResetTokenTtlMs);
const RESET_TOKEN_TTL_MS = Number.isFinite(resetTokenTtlMs) ? resetTokenTtlMs : defaultResetTokenTtlMs;
const RESET_PASSWORD_BASE_URL = process.env.RESET_PASSWORD_BASE_URL ?? 'http://localhost:5173/reset-password';

const sendError = (res: Response, status: number, payload: ErrorResponse) => {
  res.status(status).json(payload);
};

const sanitizeRegister = (body: RegisterRequest) => ({
  firstName: body.firstName?.trim(),
  lastName: body.lastName?.trim(),
  email: body.email?.trim().toLowerCase(),
  phoneNumber: body.phoneNumber?.trim(),
  password: body.password ?? '',
});

const sanitizeVerifyCode = (body: VerifyCodeRequest) => ({
  verificationId: body.verificationId?.trim(),
  code: body.code?.trim(),
});

const sanitizeLogin = (body: LoginRequest) => ({
  email: body.email?.trim().toLowerCase(),
  password: body.password ?? '',
});

const sanitizeForgotPassword = (body: ForgotPasswordRequest) => ({
  email: body.email?.trim().toLowerCase(),
});

const sanitizeResetPassword = (body: ResetPasswordRequest) => ({
  token: body.token?.trim(),
  password: body.password ?? '',
  confirmPassword: body.confirmPassword ?? '',
});

const sanitizeVerificationStatus = (body: VerificationStatusRequest) => ({
  verificationId: body.verificationId?.trim(),
});

const sanitizeSetPassword = (body: SetPasswordRequest) => ({
  password: body.password ?? '',
  confirmPassword: body.confirmPassword ?? '',
});

const router = Router();

router.post('/register', (req: Request, res: Response) => {
  const { firstName, lastName, email, phoneNumber, password } = sanitizeRegister(
    req.body as RegisterRequest
  );

  if (!firstName) {
    return sendError(res, 400, { error: 'First name is required.', field: 'firstName' });
  }
  if (!lastName) {
    return sendError(res, 400, { error: 'Last name is required.', field: 'lastName' });
  }
  if (!email) {
    return sendError(res, 400, { error: 'Email is required.', field: 'email' });
  }
  if (!emailRegex.test(email)) {
    return sendError(res, 400, { error: 'Email format is invalid.', field: 'email' });
  }
  if (!phoneNumber) {
    return sendError(res, 400, { error: 'Phone number is required.', field: 'phoneNumber' });
  }
  const parsed = parsePhoneNumberFromString(phoneNumber);
  if (!parsed || !parsed.isValid()) {
    return sendError(res, 400, { error: 'Phone number is invalid.', field: 'phoneNumber' });
  }
  if (!password) {
    return sendError(res, 400, { error: 'Password is required.', field: 'password' });
  }
  if (password.length < 8) {
    return sendError(res, 400, { error: 'Password must be at least 8 characters.', field: 'password' });
  }

  const existingUser = users.find((user) => user.email === email);
  if (existingUser) {
    return sendError(res, 409, { error: 'Email is already registered.', field: 'email' });
  }

  const user: User = {
    id: `user_${Date.now()}`,
    email,
    firstName,
    lastName,
    phoneNumber,
    verificationId: crypto.randomUUID(),
    password,
    verified: false,
    createdAt: new Date(),
  };

  const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
  users.push(user);
  verificationCodes.set(user.verificationId, verificationCode);
  console.log(`Verification code for ${user.email} (${user.verificationId}): ${verificationCode}`);

  const { password: _password, ...safeUser } = user;
  void _password;
  res.status(201).json({ user: safeUser });
});

router.post('/verify-code', (req: Request, res: Response) => {
  const { verificationId, code } = sanitizeVerifyCode(req.body as VerifyCodeRequest);

  if (!verificationId) {
    return sendError(res, 400, { error: 'Verification ID is required.', field: 'verificationId' });
  }
  if (!code) {
    return sendError(res, 400, { error: 'Verification code is required.', field: 'code' });
  }

  const expectedCode = verificationCodes.get(verificationId);
  if (!expectedCode) {
    return sendError(res, 400, { error: 'Verification code not found.', field: 'code' });
  }
  if (expectedCode !== code) {
    return sendError(res, 400, { error: 'Verification code is invalid.', field: 'code' });
  }

  const user = users.find((entry) => entry.verificationId === verificationId);
  if (!user) {
    return sendError(res, 404, { error: 'User not found.', field: 'verificationId' });
  }

  user.verified = true;
  verificationCodes.delete(verificationId);

  const token = crypto.randomUUID();
  sessions.set(token, user.email);

  const { password: _password, ...safeUser } = user;
  void _password;
  res.status(200).json({ user: safeUser, token });
});

router.get('/verification-status', (req: Request, res: Response) => {
  const { verificationId } = sanitizeVerificationStatus(
    req.query as VerificationStatusRequest
  );

  if (!verificationId) {
    return sendError(res, 400, { error: 'Verification ID is required.', field: 'verificationId' });
  }

  const user = users.find((entry) => entry.verificationId === verificationId);
  if (!user) {
    return sendError(res, 404, { error: 'User not found.', field: 'verificationId' });
  }

  return res.status(200).json({ verified: user.verified });
});

router.post('/login', (req: Request, res: Response) => {
  const { email, password } = sanitizeLogin(req.body as LoginRequest);

  if (!email) {
    return sendError(res, 400, { error: 'Email is required.', field: 'email' });
  }
  if (!emailRegex.test(email)) {
    return sendError(res, 400, { error: 'Email format is invalid.', field: 'email' });
  }
  if (!password) {
    return sendError(res, 400, { error: 'Password is required.', field: 'password' });
  }

  const user = users.find((entry) => entry.email === email);
  if (!user) {
    return sendError(res, 401, { error: 'Invalid credentials.', field: 'email' });
  }
  if (user.password !== password) {
    return sendError(res, 401, { error: 'Invalid credentials.', field: 'password' });
  }
  if (!user.verified) {
    return res.status(403).json({
      error: 'Account is not verified.',
      field: 'email',
      verificationId: user.verificationId,
    });
  }

  const token = crypto.randomUUID();
  sessions.set(token, email);

  const { password: _password, ...safeUser } = user;
  void _password;
  res.status(200).json({ user: safeUser, token });
});

router.post('/forgot-password', (req: Request, res: Response) => {
  const { email } = sanitizeForgotPassword(req.body as ForgotPasswordRequest);

  if (!email) {
    return sendError(res, 400, { error: 'Email is required.', field: 'email' });
  }
  if (!emailRegex.test(email)) {
    return sendError(res, 400, { error: 'Email format is invalid.', field: 'email' });
  }

  const user = users.find((entry) => entry.email === email);
  if (!user) {
    return sendError(res, 404, { error: 'User not found.', field: 'email' });
  }

  const token = crypto.randomUUID();
  const expiresAt = Date.now() + RESET_TOKEN_TTL_MS;
  resetTokens.set(token, { email, expiresAt });

  const resetLink = `${RESET_PASSWORD_BASE_URL}?token=${encodeURIComponent(token)}`;
  console.log(`Password reset link for ${email}: ${resetLink}`);

  return res.status(200).json({ message: 'Password reset email sent.', token });
});

router.post('/reset-password', (req: Request, res: Response) => {
  const { token, password, confirmPassword } = sanitizeResetPassword(
    req.body as ResetPasswordRequest
  );

  if (!token) {
    return sendError(res, 400, { error: 'Reset token is required.', field: 'token' });
  }
  if (!password) {
    return sendError(res, 400, { error: 'Password is required.', field: 'password' });
  }
  if (!confirmPassword) {
    return sendError(res, 400, { error: 'Confirm password is required.', field: 'confirmPassword' });
  }
  if (password.length < 8) {
    return sendError(res, 400, { error: 'Password must be at least 8 characters.', field: 'password' });
  }
  if (password !== confirmPassword) {
    return sendError(res, 400, { error: 'Passwords do not match.', field: 'confirmPassword' });
  }

  const resetEntry = resetTokens.get(token);
  if (!resetEntry) {
    return sendError(res, 403, { error: 'Reset token is invalid or expired.', field: 'token' });
  }
  if (Date.now() > resetEntry.expiresAt) {
    resetTokens.delete(token);
    return sendError(res, 403, { error: 'Reset token is invalid or expired.', field: 'token' });
  }

  const user = users.find((entry) => entry.email === resetEntry.email);
  if (!user) {
    return sendError(res, 404, { error: 'User not found.', field: 'email' });
  }

  user.password = password;
  resetTokens.delete(token);

  return res.status(200).json({ message: 'Password reset successfully.' });
});

router.post('/set-password', (req: Request, res: Response) => {
  return requireAuth(req, res, () => {
    const { password, confirmPassword } = sanitizeSetPassword(
      req.body as SetPasswordRequest
    );

    if (!password) {
      return sendError(res, 400, { error: 'Password is required.', field: 'password' });
    }
    if (!confirmPassword) {
      return sendError(res, 400, { error: 'Confirm password is required.', field: 'confirmPassword' });
    }
    if (password.length < 8) {
      return sendError(res, 400, { error: 'Password must be at least 8 characters.', field: 'password' });
    }
    if (password !== confirmPassword) {
      return sendError(res, 400, { error: 'Passwords do not match.', field: 'confirmPassword' });
    }

    const email = (req as AuthenticatedRequest).userEmail;
    if (!email) {
      return sendError(res, 403, { error: 'Invalid session token.' });
    }

    const user = users.find((entry) => entry.email === email);
    if (!user) {
      return sendError(res, 404, { error: 'User not found.', field: 'email' });
    }

    user.password = password;

    return res.status(200).json({ message: 'Password updated successfully.' });
  });
});

router.get('/me', requireAuth, (req: Request, res: Response) => {
  const email = (req as AuthenticatedRequest).userEmail;
  if (!email) {
    return sendError(res, 403, { error: 'Invalid session token.' });
  }

  const user = users.find((entry) => entry.email === email);
  if (!user) {
    return sendError(res, 404, { error: 'User not found.', field: 'email' });
  }

  const { password: _password, ...safeUser } = user;
  void _password;
  return res.status(200).json({ user: safeUser });
});

router.post('/logout', requireAuth, (req: Request, res: Response) => {
  const authHeader = req.header('authorization') ?? '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (token) {
    sessions.delete(token);
  }
  return res.status(200).json({ message: 'Logged out successfully.' });
});

export { router as authRouter };
export const __authTest = {
  users,
  verificationCodes,
  sessions,
  resetTokens,
  reset: resetAuthStore,
};

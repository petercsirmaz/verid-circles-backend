import { Router, Request, Response } from 'express';
import crypto from 'crypto';

import { users, verificationCodes, sessions, resetAuthStore } from '../store/auth';
import type { User } from '../store/auth';
import { requireAuth, AuthenticatedRequest } from '../middleware/auth';

type RegisterRequest = {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
};

type VerifyCodeRequest = {
  email: string;
  code: string;
};

type LoginRequest = {
  email: string;
  password: string;
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

const sendError = (res: Response, status: number, payload: ErrorResponse) => {
  res.status(status).json(payload);
};

const sanitizeRegister = (body: RegisterRequest) => ({
  firstName: body.firstName?.trim(),
  lastName: body.lastName?.trim(),
  email: body.email?.trim().toLowerCase(),
  password: body.password ?? '',
});

const sanitizeVerifyCode = (body: VerifyCodeRequest) => ({
  email: body.email?.trim().toLowerCase(),
  code: body.code?.trim(),
});

const sanitizeLogin = (body: LoginRequest) => ({
  email: body.email?.trim().toLowerCase(),
  password: body.password ?? '',
});

const sanitizeSetPassword = (body: SetPasswordRequest) => ({
  password: body.password ?? '',
  confirmPassword: body.confirmPassword ?? '',
});

const router = Router();

router.post('/register', (req: Request, res: Response) => {
  const { firstName, lastName, email, password } = sanitizeRegister(
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
    password,
    verified: false,
    createdAt: new Date(),
  };

  const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
  users.push(user);
  verificationCodes.set(email, verificationCode);

  const { password: _password, ...safeUser } = user;
  void _password;
  res.status(201).json({ user: safeUser });
});

router.post('/verify-code', (req: Request, res: Response) => {
  const { email, code } = sanitizeVerifyCode(req.body as VerifyCodeRequest);

  if (!email) {
    return sendError(res, 400, { error: 'Email is required.', field: 'email' });
  }
  if (!emailRegex.test(email)) {
    return sendError(res, 400, { error: 'Email format is invalid.', field: 'email' });
  }
  if (!code) {
    return sendError(res, 400, { error: 'Verification code is required.', field: 'code' });
  }

  const expectedCode = verificationCodes.get(email);
  if (!expectedCode) {
    return sendError(res, 400, { error: 'Verification code not found.', field: 'code' });
  }
  if (expectedCode !== code) {
    return sendError(res, 400, { error: 'Verification code is invalid.', field: 'code' });
  }

  const user = users.find((entry) => entry.email === email);
  if (!user) {
    return sendError(res, 404, { error: 'User not found.', field: 'email' });
  }

  user.verified = true;
  verificationCodes.delete(email);

  const token = crypto.randomUUID();
  sessions.set(token, email);

  const { password: _password, ...safeUser } = user;
  void _password;
  res.status(200).json({ user: safeUser, token });
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
    return sendError(res, 403, { error: 'Account is not verified.', field: 'email' });
  }

  const token = crypto.randomUUID();
  sessions.set(token, email);

  const { password: _password, ...safeUser } = user;
  void _password;
  res.status(200).json({ user: safeUser, token });
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

export { router as authRouter };
export const __authTest = {
  users,
  verificationCodes,
  sessions,
  reset: resetAuthStore,
};

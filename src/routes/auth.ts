import { Router, Request, Response } from 'express';

type User = {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  password: string;
  verified: boolean;
  createdAt: Date;
};

type RegisterRequest = {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
};

type ErrorResponse = {
  error: string;
  field?: string;
};

const users: User[] = [];
const verificationCodes: Map<string, string> = new Map();

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

export { router as authRouter };

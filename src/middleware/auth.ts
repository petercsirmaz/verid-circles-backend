import { Request, Response, NextFunction } from 'express';

import { sessions } from '../store/auth';

type AuthenticatedRequest = Request & { userEmail?: string };

const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.header('authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization token is required.' });
  }

  const token = authHeader.replace('Bearer ', '').trim();
  const email = sessions.get(token);
  if (!email) {
    return res.status(403).json({ error: 'Invalid session token.' });
  }

  (req as AuthenticatedRequest).userEmail = email;
  return next();
};

export { requireAuth, AuthenticatedRequest };

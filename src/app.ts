import express, { Request, Response } from 'express';
import cors from 'cors';

import { authRouter } from './routes/auth';
import { requireAuth, AuthenticatedRequest } from './middleware/auth';

const app = express();

app.use(cors());
app.use(express.json());

app.get('/api/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use('/api/auth', authRouter);

if (process.env.NODE_ENV === 'test') {
  app.get('/__test/auth-email', requireAuth, (req: Request, res: Response) => {
    const email = (req as AuthenticatedRequest).userEmail;
    res.json({ email });
  });
}

export { app };

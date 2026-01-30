import express, { Request, Response } from 'express';
import cors from 'cors';

import { authRouter } from './routes/auth';

const app = express();

app.use(cors());
app.use(express.json());

app.get('/api/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use('/api/auth', authRouter);

export { app };

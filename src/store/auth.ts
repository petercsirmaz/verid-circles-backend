type User = {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  phoneNumber: string;
  verificationId: string;
  password: string;
  verified: boolean;
  createdAt: Date;
};

const users: User[] = [];
const verificationCodes: Map<string, string> = new Map();
const sessions: Map<string, string> = new Map();
type ResetTokenEntry = {
  email: string;
  expiresAt: number;
};

const resetTokens: Map<string, ResetTokenEntry> = new Map();

const resetAuthStore = () => {
  users.length = 0;
  verificationCodes.clear();
  sessions.clear();
  resetTokens.clear();
};

export { users, verificationCodes, sessions, resetTokens, resetAuthStore };
export type { ResetTokenEntry };
export type { User };

type User = {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  phoneNumber: string;
  password: string;
  verified: boolean;
  createdAt: Date;
};

const users: User[] = [];
const verificationCodes: Map<string, string> = new Map();
const sessions: Map<string, string> = new Map();

const resetAuthStore = () => {
  users.length = 0;
  verificationCodes.clear();
  sessions.clear();
};

export { users, verificationCodes, sessions, resetAuthStore };
export type { User };

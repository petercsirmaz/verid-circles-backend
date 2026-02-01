import request from 'supertest';

import { app } from '../../src/app';
import { __authTest } from '../../src/routes/auth';

describe('POST /api/auth/register', () => {
  beforeEach(() => {
    __authTest.reset();
  });

  it('creates a user and omits password in response', async () => {
    const email = `test.user.${Date.now()}@example.com`;
    const phoneNumber = '+14155552671';

    const response = await request(app)
      .post('/api/auth/register')
      .send({
        firstName: 'Test',
        lastName: 'User',
        email,
        phoneNumber,
        password: 'password123',
      });

    expect(response.status).toBe(201);
    expect(response.body.user).toBeDefined();
    expect(response.body.user.email).toBe(email);
    expect(response.body.user.phoneNumber).toBe(phoneNumber);
    expect(response.body.user.verificationId).toBeDefined();
    expect(response.body.user.password).toBeUndefined();
  });

  it('rejects invalid email format', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send({
        firstName: 'Test',
        lastName: 'User',
        email: 'not-an-email',
        phoneNumber: '+14155552672',
        password: 'password123',
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBeDefined();
    expect(response.body.field).toBe('email');
  });

  it('rejects invalid phone number', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send({
        firstName: 'Test',
        lastName: 'User',
        email: `phone.user.${Date.now()}@example.com`,
        phoneNumber: '12345',
        password: 'password123',
      });

    expect(response.status).toBe(400);
    expect(response.body.field).toBe('phoneNumber');
  });

  it('rejects missing phone number', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send({
        firstName: 'Test',
        lastName: 'User',
        email: `nophone.user.${Date.now()}@example.com`,
        password: 'password123',
      });

    expect(response.status).toBe(400);
    expect(response.body.field).toBe('phoneNumber');
  });

  it('rejects duplicate email', async () => {
    const email = `dupe.user.${Date.now()}@example.com`;
    const phoneNumber = '+14155552673';

    await request(app).post('/api/auth/register').send({
      firstName: 'Dupe',
      lastName: 'User',
      email,
      phoneNumber,
      password: 'password123',
    });

    const response = await request(app).post('/api/auth/register').send({
      firstName: 'Dupe',
      lastName: 'User',
      email,
      phoneNumber,
      password: 'password123',
    });

    expect(response.status).toBe(409);
    expect(response.body.error).toBeDefined();
    expect(response.body.field).toBe('email');
  });
});

describe('POST /api/auth/verify-code', () => {
  beforeEach(() => {
    __authTest.reset();
  });

  it('verifies a user and returns a token', async () => {
    const email = `verify.user.${Date.now()}@example.com`;

    const registerResponse = await request(app).post('/api/auth/register').send({
      firstName: 'Verify',
      lastName: 'User',
      email,
      phoneNumber: '+14155552674',
      password: 'password123',
    });

    const verificationId = registerResponse.body.user.verificationId;
    const code = __authTest.verificationCodes.get(verificationId);
    expect(code).toBeDefined();

    const response = await request(app).post('/api/auth/verify-code').send({
      verificationId,
      code,
    });

    expect(response.status).toBe(200);
    expect(response.body.token).toBeDefined();
    expect(response.body.user).toBeDefined();
    expect(response.body.user.email).toBe(email);
  });

  it('rejects invalid verification code', async () => {
    const email = `badcode.user.${Date.now()}@example.com`;

    const registerResponse = await request(app).post('/api/auth/register').send({
      firstName: 'Bad',
      lastName: 'Code',
      email,
      phoneNumber: '+14155552675',
      password: 'password123',
    });

    const verificationId = registerResponse.body.user.verificationId;
    const response = await request(app).post('/api/auth/verify-code').send({
      verificationId,
      code: '000000',
    });

    expect(response.status).toBe(400);
    expect(response.body.error).toBeDefined();
    expect(response.body.field).toBe('code');
  });

  it('returns 400 when code is missing', async () => {
    const response = await request(app).post('/api/auth/verify-code').send({
      verificationId: 'missing-verification-id',
    });

    expect(response.status).toBe(400);
    expect(response.body.field).toBe('code');
  });
});

describe('POST /api/auth/login', () => {
  beforeEach(() => {
    __authTest.reset();
  });

  it('logs in a verified user and returns a token', async () => {
    const email = `login.user.${Date.now()}@example.com`;
    const password = 'password123';

    const registerResponse = await request(app).post('/api/auth/register').send({
      firstName: 'Login',
      lastName: 'User',
      email,
      phoneNumber: '+14155552676',
      password,
    });

    const verificationId = registerResponse.body.user.verificationId;
    const code = __authTest.verificationCodes.get(verificationId);
    expect(code).toBeDefined();

    await request(app).post('/api/auth/verify-code').send({
      verificationId,
      code,
    });

    const response = await request(app).post('/api/auth/login').send({
      email,
      password,
    });

    expect(response.status).toBe(200);
    expect(response.body.token).toBeDefined();
    expect(response.body.user).toBeDefined();
    expect(response.body.user.email).toBe(email);
  });

  it('rejects login for unverified user', async () => {
    const email = `unverified.user.${Date.now()}@example.com`;

    await request(app).post('/api/auth/register').send({
      firstName: 'Unverified',
      lastName: 'User',
      email,
      phoneNumber: '+14155552677',
      password: 'password123',
    });

    const response = await request(app).post('/api/auth/login').send({
      email,
      password: 'password123',
    });

    expect(response.status).toBe(403);
    expect(response.body.error).toBeDefined();
    expect(response.body.field).toBe('email');
    expect(response.body.verificationId).toBeDefined();
  });

  it('rejects invalid password', async () => {
    const email = `wrongpass.user.${Date.now()}@example.com`;

    const registerResponse = await request(app).post('/api/auth/register').send({
      firstName: 'Wrong',
      lastName: 'Password',
      email,
      phoneNumber: '+14155552678',
      password: 'password123',
    });

    const verificationId = registerResponse.body.user.verificationId;
    const code = __authTest.verificationCodes.get(verificationId);
    expect(code).toBeDefined();

    await request(app).post('/api/auth/verify-code').send({
      verificationId,
      code,
    });

    const response = await request(app).post('/api/auth/login').send({
      email,
      password: 'password000',
    });

    expect(response.status).toBe(401);
    expect(response.body.error).toBeDefined();
    expect(response.body.field).toBe('password');
  });

  it('returns 400 when password is missing', async () => {
    const response = await request(app).post('/api/auth/login').send({
      email: 'missing.password@example.com',
    });

    expect(response.status).toBe(400);
    expect(response.body.field).toBe('password');
  });
});

describe('POST /api/auth/set-password', () => {
  beforeEach(() => {
    __authTest.reset();
  });

  it('updates password for authenticated user', async () => {
    const email = `setpass.user.${Date.now()}@example.com`;

    const registerResponse = await request(app).post('/api/auth/register').send({
      firstName: 'Set',
      lastName: 'Password',
      email,
      phoneNumber: '+14155552679',
      password: 'password123',
    });

    const verificationId = registerResponse.body.user.verificationId;
    const code = __authTest.verificationCodes.get(verificationId);
    expect(code).toBeDefined();

    const verifyResponse = await request(app).post('/api/auth/verify-code').send({
      verificationId,
      code,
    });

    const token = verifyResponse.body.token;
    expect(token).toBeDefined();

    const response = await request(app)
      .post('/api/auth/set-password')
      .set('Authorization', `Bearer ${token}`)
      .send({
        password: 'newpassword123',
        confirmPassword: 'newpassword123',
      });

    expect(response.status).toBe(200);
    expect(response.body.message).toBeDefined();
  });

  it('rejects missing auth token', async () => {
    const response = await request(app).post('/api/auth/set-password').send({
      password: 'newpassword123',
      confirmPassword: 'newpassword123',
    });

    expect(response.status).toBe(401);
    expect(response.body.error).toBeDefined();
  });

  it('rejects invalid auth token', async () => {
    const response = await request(app)
      .post('/api/auth/set-password')
      .set('Authorization', 'Bearer invalid-token')
      .send({
        password: 'newpassword123',
        confirmPassword: 'newpassword123',
      });

    expect(response.status).toBe(403);
    expect(response.body.error).toBeDefined();
  });

  it('rejects mismatched passwords', async () => {
    const email = `mismatch.user.${Date.now()}@example.com`;

    const registerResponse = await request(app).post('/api/auth/register').send({
      firstName: 'Mismatch',
      lastName: 'User',
      email,
      phoneNumber: '+14155552680',
      password: 'password123',
    });

    const verificationId = registerResponse.body.user.verificationId;
    const code = __authTest.verificationCodes.get(verificationId);
    expect(code).toBeDefined();

    const verifyResponse = await request(app).post('/api/auth/verify-code').send({
      verificationId,
      code,
    });

    const token = verifyResponse.body.token;

    const response = await request(app)
      .post('/api/auth/set-password')
      .set('Authorization', `Bearer ${token}`)
      .send({
        password: 'newpassword123',
        confirmPassword: 'newpassword000',
      });

    expect(response.status).toBe(400);
    expect(response.body.field).toBe('confirmPassword');
  });
});

describe('Auth middleware', () => {
  beforeEach(() => {
    __authTest.reset();
  });

  it('attaches user email to request', async () => {
    const email = `middleware.user.${Date.now()}@example.com`;

    const registerResponse = await request(app).post('/api/auth/register').send({
      firstName: 'Middleware',
      lastName: 'User',
      email,
      phoneNumber: '+14155552681',
      password: 'password123',
    });

    const verificationId = registerResponse.body.user.verificationId;
    const code = __authTest.verificationCodes.get(verificationId);
    expect(code).toBeDefined();

    const verifyResponse = await request(app).post('/api/auth/verify-code').send({
      verificationId,
      code,
    });

    const token = verifyResponse.body.token;
    expect(token).toBeDefined();

    const response = await request(app)
      .get('/__test/auth-email')
      .set('Authorization', `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body.email).toBe(email);
  });
});

describe('GET /api/auth/me', () => {
  beforeEach(() => {
    __authTest.reset();
  });

  it('returns current user for authenticated request', async () => {
    const email = `me.user.${Date.now()}@example.com`;

    const registerResponse = await request(app).post('/api/auth/register').send({
      firstName: 'Me',
      lastName: 'User',
      email,
      phoneNumber: '+14155552682',
      password: 'password123',
    });

    const verificationId = registerResponse.body.user.verificationId;
    const code = __authTest.verificationCodes.get(verificationId);
    expect(code).toBeDefined();

    const verifyResponse = await request(app).post('/api/auth/verify-code').send({
      verificationId,
      code,
    });

    const token = verifyResponse.body.token;
    expect(token).toBeDefined();

    const response = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body.user).toBeDefined();
    expect(response.body.user.email).toBe(email);
  });

  it('rejects request without token', async () => {
    const response = await request(app).get('/api/auth/me');

    expect(response.status).toBe(401);
    expect(response.body.error).toBeDefined();
  });
});

describe('POST /api/auth/logout', () => {
  beforeEach(() => {
    __authTest.reset();
  });

  it('removes the session token', async () => {
    const email = `logout.user.${Date.now()}@example.com`;

    const registerResponse = await request(app).post('/api/auth/register').send({
      firstName: 'Logout',
      lastName: 'User',
      email,
      phoneNumber: '+14155552683',
      password: 'password123',
    });

    const verificationId = registerResponse.body.user.verificationId;
    const code = __authTest.verificationCodes.get(verificationId);
    expect(code).toBeDefined();

    const verifyResponse = await request(app).post('/api/auth/verify-code').send({
      verificationId,
      code,
    });

    const token = verifyResponse.body.token;
    expect(token).toBeDefined();

    const logoutResponse = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${token}`);

    expect(logoutResponse.status).toBe(200);
    expect(__authTest.sessions.has(token)).toBe(false);
  });

  it('rejects logout without token', async () => {
    const response = await request(app).post('/api/auth/logout');

    expect(response.status).toBe(401);
    expect(response.body.error).toBeDefined();
  });
});

describe('GET /api/auth/verification-status', () => {
  beforeEach(() => {
    __authTest.reset();
  });

  it('returns verification status for a valid verification id', async () => {
    const email = `status.user.${Date.now()}@example.com`;

    const registerResponse = await request(app).post('/api/auth/register').send({
      firstName: 'Status',
      lastName: 'User',
      email,
      phoneNumber: '+14155552684',
      password: 'password123',
    });

    const verificationId = registerResponse.body.user.verificationId;
    expect(verificationId).toBeDefined();

    const response = await request(app)
      .get('/api/auth/verification-status')
      .query({ verificationId });

    expect(response.status).toBe(200);
    expect(response.body.verified).toBe(false);
  });

  it('returns 404 for unknown verification id', async () => {
    const response = await request(app)
      .get('/api/auth/verification-status')
      .query({ verificationId: 'missing-verification-id' });

    expect(response.status).toBe(404);
    expect(response.body.field).toBe('verificationId');
  });
});

describe('POST /api/auth/forgot-password', () => {
  beforeEach(() => {
    __authTest.reset();
  });

  it('issues a reset token for existing user', async () => {
    const email = `forgot.user.${Date.now()}@example.com`;

    await request(app).post('/api/auth/register').send({
      firstName: 'Forgot',
      lastName: 'User',
      email,
      phoneNumber: '+14155552685',
      password: 'password123',
    });

    const response = await request(app).post('/api/auth/forgot-password').send({ email });

    expect(response.status).toBe(200);
    expect(response.body.message).toBeDefined();
    expect(response.body.token).toBeDefined();
  });

  it('returns 404 for unknown email', async () => {
    const response = await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'missing.user@example.com' });

    expect(response.status).toBe(404);
    expect(response.body.field).toBe('email');
  });
});

describe('POST /api/auth/reset-password', () => {
  beforeEach(() => {
    __authTest.reset();
  });

  it('resets password with a valid token', async () => {
    const email = `reset.user.${Date.now()}@example.com`;

    await request(app).post('/api/auth/register').send({
      firstName: 'Reset',
      lastName: 'User',
      email,
      phoneNumber: '+14155552686',
      password: 'password123',
    });

    const forgotResponse = await request(app)
      .post('/api/auth/forgot-password')
      .send({ email });

    const token = forgotResponse.body.token;
    expect(token).toBeDefined();

    const response = await request(app).post('/api/auth/reset-password').send({
      token,
      password: 'newpassword123',
      confirmPassword: 'newpassword123',
    });

    expect(response.status).toBe(200);
    expect(response.body.message).toBeDefined();
  });

  it('rejects invalid reset token', async () => {
    const response = await request(app).post('/api/auth/reset-password').send({
      token: 'invalid-token',
      password: 'newpassword123',
      confirmPassword: 'newpassword123',
    });

    expect(response.status).toBe(403);
    expect(response.body.field).toBe('token');
  });
});

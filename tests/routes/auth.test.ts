import request from 'supertest';

import { app } from '../../src/app';
import { __authTest } from '../../src/routes/auth';

describe('POST /api/auth/register', () => {
  beforeEach(() => {
    __authTest.reset();
  });

  it('creates a user and omits password in response', async () => {
    const email = `test.user.${Date.now()}@example.com`;

    const response = await request(app)
      .post('/api/auth/register')
      .send({
        firstName: 'Test',
        lastName: 'User',
        email,
        password: 'password123',
      });

    expect(response.status).toBe(201);
    expect(response.body.user).toBeDefined();
    expect(response.body.user.email).toBe(email);
    expect(response.body.user.password).toBeUndefined();
  });

  it('rejects invalid email format', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send({
        firstName: 'Test',
        lastName: 'User',
        email: 'not-an-email',
        password: 'password123',
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBeDefined();
    expect(response.body.field).toBe('email');
  });

  it('rejects duplicate email', async () => {
    const email = `dupe.user.${Date.now()}@example.com`;

    await request(app).post('/api/auth/register').send({
      firstName: 'Dupe',
      lastName: 'User',
      email,
      password: 'password123',
    });

    const response = await request(app).post('/api/auth/register').send({
      firstName: 'Dupe',
      lastName: 'User',
      email,
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

    await request(app).post('/api/auth/register').send({
      firstName: 'Verify',
      lastName: 'User',
      email,
      password: 'password123',
    });

    const code = __authTest.verificationCodes.get(email);
    expect(code).toBeDefined();

    const response = await request(app).post('/api/auth/verify-code').send({
      email,
      code,
    });

    expect(response.status).toBe(200);
    expect(response.body.token).toBeDefined();
    expect(response.body.user).toBeDefined();
    expect(response.body.user.email).toBe(email);
  });

  it('rejects invalid verification code', async () => {
    const email = `badcode.user.${Date.now()}@example.com`;

    await request(app).post('/api/auth/register').send({
      firstName: 'Bad',
      lastName: 'Code',
      email,
      password: 'password123',
    });

    const response = await request(app).post('/api/auth/verify-code').send({
      email,
      code: '000000',
    });

    expect(response.status).toBe(400);
    expect(response.body.error).toBeDefined();
    expect(response.body.field).toBe('code');
  });

  it('returns 400 when code is missing', async () => {
    const response = await request(app).post('/api/auth/verify-code').send({
      email: 'missing.code@example.com',
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

    await request(app).post('/api/auth/register').send({
      firstName: 'Login',
      lastName: 'User',
      email,
      password,
    });

    const code = __authTest.verificationCodes.get(email);
    expect(code).toBeDefined();

    await request(app).post('/api/auth/verify-code').send({
      email,
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
      password: 'password123',
    });

    const response = await request(app).post('/api/auth/login').send({
      email,
      password: 'password123',
    });

    expect(response.status).toBe(403);
    expect(response.body.error).toBeDefined();
    expect(response.body.field).toBe('email');
  });

  it('rejects invalid password', async () => {
    const email = `wrongpass.user.${Date.now()}@example.com`;

    await request(app).post('/api/auth/register').send({
      firstName: 'Wrong',
      lastName: 'Password',
      email,
      password: 'password123',
    });

    const code = __authTest.verificationCodes.get(email);
    expect(code).toBeDefined();

    await request(app).post('/api/auth/verify-code').send({
      email,
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

    await request(app).post('/api/auth/register').send({
      firstName: 'Set',
      lastName: 'Password',
      email,
      password: 'password123',
    });

    const code = __authTest.verificationCodes.get(email);
    expect(code).toBeDefined();

    const verifyResponse = await request(app).post('/api/auth/verify-code').send({
      email,
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

  it('rejects mismatched passwords', async () => {
    const email = `mismatch.user.${Date.now()}@example.com`;

    await request(app).post('/api/auth/register').send({
      firstName: 'Mismatch',
      lastName: 'User',
      email,
      password: 'password123',
    });

    const code = __authTest.verificationCodes.get(email);
    expect(code).toBeDefined();

    const verifyResponse = await request(app).post('/api/auth/verify-code').send({
      email,
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

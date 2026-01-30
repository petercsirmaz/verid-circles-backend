import request from 'supertest';

import { app } from '../../src/app';

describe('POST /api/auth/register', () => {
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

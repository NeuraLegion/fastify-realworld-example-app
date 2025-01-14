import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';

describe('/api/users', () => {
  const timeout = 300000;
  jest.setTimeout(timeout);

  let runner!: SecRunner;

  beforeAll(async () => {
    runner = new SecRunner({ hostname: 'app.neuralegion.com' });
    await runner.init();
  });

  afterAll(() => runner.clear());

  describe('POST /api/users/login', () => {
    it('should not have vulnerabilities', async () => {
      await runner
        .createScan({
          tests: [
            TestType.BRUTE_FORCE_LOGIN,
            TestType.CSRF,
            TestType.SQLI,
            TestType.XSS,
            'insecure_output_handling'
          ],
          attackParamLocations: [AttackParamLocation.BODY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'POST',
          url: 'https://localhost:8000/api/users/login',
          headers: { 'Content-Type': 'application/json' },
          body: { user: { email: 'example@example.com', password: 'password123' } }
        });
    });
  });

  describe('POST /api/users', () => {
    it('should not have vulnerabilities', async () => {
      await runner
        .createScan({
          tests: [
            TestType.BRUTE_FORCE_LOGIN,
            TestType.CSRF,
            TestType.MASS_ASSIGNMENT,
            TestType.SQLI,
            TestType.XSS
          ],
          attackParamLocations: [AttackParamLocation.BODY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'POST',
          url: 'https://localhost:8000/api/users',
          headers: { 'Content-Type': 'application/json' },
          body: { user: { username: 'newuser', email: 'newuser@example.com', password: 'password123' } }
        });
    });
  });
});

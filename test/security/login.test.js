import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('Login API Security Tests', () => {
  let runner!: SecRunner;
  let baseUrl!: string;

  beforeAll(async () => {
    // Setup application and get baseUrl
  });

  afterAll(() => {
    // Teardown application
  });

  beforeEach(async () => {
    runner = new SecRunner({
      // Config
    });

    await runner.init();
  });

  afterEach(() => runner.clear());

  it('POST /api/users/login', async () => {
    await runner
      .createScan({
        tests: [TestType.BRUTE_FORCE_LOGIN, TestType.CSRF, TestType.SQLI, TestType.XSS],
        attackParamLocations: ["body", "query"]
      })
      .threshold("MEDIUM")
      .timeout(15 * 60 * 1000)
      .run({
        method: 'POST',
        url: `${baseUrl}/api/users/login`,
        headers: { 'Content-Type': 'application/json' },
        body: { user: { email: 'example@example.com', password: 'password123' } }
      });
  });
});
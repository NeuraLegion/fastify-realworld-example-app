import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';
import { Severity } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('API Security Tests', () => {
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

  describe('GET /api/user', () => {
    it('should not have security issues', async () => {
      await runner
        .createScan({
          tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, 'excessive_data_exposure']
        })
        .threshold(Severity.MEDIUM)
        .timeout(300000)
        .run({
          method: 'GET',
          url: 'http://localhost:3000/api/user',
          headers: {
            Authorization: 'Bearer <token>'
          }
        });
    });
  });

  describe('PUT /api/user', () => {
    it('should pass security tests', async () => {
      await runner
        .createScan({
          tests: [TestType.JWT, TestType.CSRF, TestType.BRUTE_FORCE_LOGIN, TestType.MASS_ASSIGNMENT, TestType.SQLI, TestType.XSS],
          attackParamLocations: ['body', 'query', 'headers']
        })
        .threshold(Severity.MEDIUM)
        .timeout(15 * 60 * 1000)
        .run({
          method: 'PUT',
          url: `${baseUrl}/api/user`,
          headers: {
            Authorization: 'Bearer <token>',
            'Content-Type': 'application/json'
          },
          body: {
            user: {
              username: 'updateduser',
              email: 'updateduser@example.com',
              password: 'newpassword123'
            }
          }
        });
    });
  });
});
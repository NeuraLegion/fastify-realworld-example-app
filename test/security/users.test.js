import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('API Security Tests', () => {
  let runner;
  let baseUrl = 'http://localhost:3000/api';

  beforeAll(async () => {
    // Setup application if needed
  });

  afterAll(() => {
    // Teardown application if needed
  });

  beforeEach(async () => {
    runner = new SecRunner({
      hostname: 'app.neuralegion.com'
    });

    await runner.init();
  });

  afterEach(() => runner.clear());

  it('POST /users', async () => {
    await runner
      .createScan({
        tests: [
          TestType.BRUTE_FORCE_LOGIN,
          TestType.CSRF,
          'excessive_data_exposure',
          TestType.MASS_ASSIGNMENT,
          TestType.SQLI,
          TestType.XSS
        ],
        attackParamLocations: ['body', 'query', 'path']
      })
      .threshold('MEDIUM')
      .timeout(300000) // 5 minutes
      .run({
        method: 'POST',
        url: `${baseUrl}/users`,
        headers: {
          'Content-Type': 'application/json'
        },
        body: {
          user: {
            username: 'newuser',
            email: 'newuser@example.com',
            password: 'password123'
          }
        }
      });
  });
});
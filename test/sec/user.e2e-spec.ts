import { SecRunner } from '@sectester/runner';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

describe('/api/user', () => {
  const timeout = 300000;
  jest.setTimeout(timeout);

  let runner!: SecRunner;
  let baseUrl!: string;

  beforeAll(async () => {
    runner = new SecRunner({ hostname: 'app.neuralegion.com' });
    await runner.init();
    baseUrl = 'https://localhost:8000';
  });

  afterAll(() => runner.clear());

  it('GET /api/user should not have broken access control, jwt issues, or excessive data exposure', async () => {
    await runner
      .createScan({
        tests: ['broken_access_control', TestType.JWT, 'excessive_data_exposure'],
        attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.QUERY, AttackParamLocation.BODY]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: `${baseUrl}/api/user`,
        headers: { Authorization: 'Bearer <token>' }
      });
  });

  it('PUT /api/user should not have vulnerabilities', async () => {
    await runner
      .createScan({
        tests: [
          TestType.JWT,
          TestType.BRUTE_FORCE_LOGIN,
          TestType.CSRF,
          TestType.MASS_ASSIGNMENT,
          TestType.SQLI,
          TestType.XSS
        ],
        attackParamLocations: [
          AttackParamLocation.BODY,
          AttackParamLocation.HEADER
        ]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'PUT',
        url: `${baseUrl}/api/user`,
        headers: {
          Authorization: 'Bearer <token>',
          'Content-Type': 'application/json'
        },
        body: {
          user: {
            email: 'updated@example.com',
            password: 'newpassword123'
          }
        }
      });
  });
});

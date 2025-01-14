import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation } from '@sectester/scan';

describe('/profiles', () => {
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

  it('GET /profiles/johndoe', async () => {
    await runner
      .createScan({
        tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, TestType.EXCESSIVE_DATA_EXPOSURE],
        attackParamLocations: [AttackParamLocation.PATH]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: `${baseUrl}/profiles/johndoe`,
        headers: { Authorization: 'Token optional_jwt_token' }
      });
  });

  describe('/johndoe/follow', () => {
    it('should not have jwt, csrf, broken_access_control, xss vulnerabilities', async () => {
      await runner
        .createScan({
          tests: [TestType.JWT, TestType.CSRF, 'broken_access_control', TestType.XSS],
          attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'POST',
          url: `${baseUrl}/profiles/johndoe/follow`,
          headers: { Authorization: 'Token required_jwt_token' },
          body: {}
        });
    });
  });
});

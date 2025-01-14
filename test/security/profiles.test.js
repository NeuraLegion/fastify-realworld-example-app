import { SecRunner, SecScan } from '@sectester/runner';
import { Severity, TestType } from '@sectester/scan';

describe('/profiles', () => {
  let runner;
  let scan;
  const timeout = 300000;
  const baseUrl = 'http://localhost:3000';

  beforeAll(async () => {
    runner = new SecRunner({ hostname: 'app.neuralegion.com' });
    await runner.init();
  });

  afterAll(async () => {
    await runner.clear();
  });

  describe('/johndoe/follow', () => {
    it('should not have security issues', async () => {
      scan = runner.createScan({
        tests: [TestType.JWT, 'broken_access_control', TestType.CSRF, TestType.HTTP_METHOD_FUZZING],
        attackParamLocations: ['header', 'body', 'query']
      }).threshold(Severity.MEDIUM).timeout(timeout);

      await scan.run({
        method: 'DELETE',
        url: `${baseUrl}/profiles/johndoe/follow`,
        headers: { 'Authorization': 'Token required_jwt_token' }
      });
    });
  });
});
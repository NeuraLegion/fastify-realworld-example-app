import { SecRunner } from '@sectester/runner';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('Security Tests for /profiles', () => {
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

  describe('GET /profiles/johndoe', () => {
    it('should pass security tests', async () => {
      await runner
        .createScan({
          tests: [
            'broken_access_control',
            TestType.ID_ENUMERATION,
            'excessive_data_exposure'
          ]
        })
        .threshold(Severity.MEDIUM)
        .timeout(300000)
        .run({
          method: 'GET',
          url: `${baseUrl}/profiles/johndoe`
        });
    });
  });

  describe('POST /profiles/johndoe/follow', () => {
    it('should pass security tests', async () => {
      await runner
        .createScan({
          tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.CSRF, TestType.JWT],
          attackParamLocations: [/* appropriate locations */]
        })
        .threshold(Severity.MEDIUM)
        .timeout(15 * 60 * 1000)
        .run({
          method: 'POST',
          url: `${baseUrl}/profiles/johndoe/follow`,
          headers: {
            'Authorization': 'Bearer <token>'
          },
          body: {}
        });
    });
  });

  describe('DELETE /profiles/johndoe/follow', () => {
    it('should pass security tests', async () => {
      await runner
        .createScan({
          tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.CSRF, TestType.JWT, 'http_method_fuzzing'],
          attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.BODY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(300000) // 5 minutes
        .run({
          method: 'DELETE',
          url: `${baseUrl}/profiles/johndoe/follow`,
          headers: {
            Authorization: 'Bearer <token>'
          },
          body: {}
        });
    });
  });
});
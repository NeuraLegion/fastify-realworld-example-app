import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('Articles API Security Tests', () => {
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

  describe('GET /articles/feed', () => {
    it('should pass security tests', async () => {
      await runner
        .createScan({
          tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.HTTP_METHOD_FUZZING],
          attackParamLocations: [/* appropriate locations */]
        })
        .threshold(Severity.MEDIUM)
        .timeout(15 * 60 * 1000)
        .run({
          method: 'GET',
          url: `${baseUrl}/articles/feed`,
          headers: {
            Authorization: 'Token jwt.token.here'
          },
          query: {
            limit: '20',
            offset: '0'
          }
        });
    });
  });

  describe('POST /articles', () => {
    it('should pass security tests', async () => {
      await runner
        .createScan({
          tests: [TestType.JWT, TestType.CSRF, TestType.MASS_ASSIGNMENT, TestType.XSS, TestType.SQLI],
          attackParamLocations: ['body', 'query', 'headers']
        })
        .threshold(Severity.MEDIUM)
        .timeout(300000) // 5 minutes
        .run({
          method: 'POST',
          url: `${baseUrl}/articles`,
          headers: {
            'Authorization': 'Token jwt.token.here',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            article: {
              title: 'string',
              description: 'string',
              body: 'string',
              tagList: ['string']
            }
          })
        });
    });
  });

  describe('DELETE /articles/{slug}', () => {
    it('should perform security tests', async () => {
      await runner
        .createScan({
          tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, TestType.HTTP_METHOD_FUZZING],
          attackParamLocations: [AttackParamLocation.PATH]
        })
        .threshold(Severity.MEDIUM)
        .timeout(300000) // 5 minutes
        .run({
          method: 'DELETE',
          url: `${baseUrl}/articles/{slug}`,
          headers: {
            Authorization: 'Token jwt.token.here'
          }
        });
    });
  });

  describe('POST /articles/{slug}/favorite', () => {
    it('should pass security tests', async () => {
      await runner
        .createScan({
          tests: [
            TestType.JWT,
            TestType.CSRF,
            TestType.BROKEN_ACCESS_CONTROL,
            TestType.HTTP_METHOD_FUZZING,
            TestType.MASS_ASSIGNMENT
          ]
        })
        .threshold(Severity.MEDIUM)
        .timeout(15 * 60 * 1000)
        .run({
          method: 'POST',
          url: `${baseUrl}/articles/{slug}/favorite`,
          headers: {
            Authorization: 'Token jwt.token.here'
          },
          body: {}
        });
    });
  });

  describe('DELETE /articles/{slug}/favorite', () => {
    it('should pass security tests', async () => {
      await runner
        .createScan({
          tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, TestType.CSRF, TestType.HTTP_METHOD_FUZZING],
          attackParamLocations: [/* specify locations if needed */]
        })
        .threshold(Severity.MEDIUM)
        .timeout(15 * 60 * 1000) // 15 minutes
        .run({
          method: 'DELETE',
          url: `${baseUrl}/articles/{slug}/favorite`,
          headers: {
            Authorization: 'Token jwt.token.here'
          }
        });
    });
  });

  describe('DELETE /articles/example-article/comments/1', () => {
    it('should pass security tests', async () => {
      await runner
        .createScan({
          tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, TestType.ID_ENUMERATION],
          attackParamLocations: ['path']
        })
        .threshold('medium')
        .timeout(15 * 60 * 1000)
        .run({
          method: 'DELETE',
          url: `${baseUrl}/articles/example-article/comments/1`,
          headers: [{ name: 'Authorization', value: 'Bearer <token>' }]
        });
    });
  });
});
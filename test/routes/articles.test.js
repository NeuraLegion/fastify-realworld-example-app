import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';
import { Severity } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('Articles API Security Tests', () => {
  let runner!: SecRunner;
  let baseUrl = 'http://localhost:3000';

  beforeAll(async () => {
    // Setup application and get baseUrl
  });

  afterAll(() => {
    // Teardown application
  });

  beforeEach(async () => {
    runner = new SecRunner({
      hostname: 'app.neuralegion.com'
    });

    await runner.init();
  });

  afterEach(() => runner.clear());

  describe('GET /articles', () => {
    it('should not have excessive data exposure, sqli, xss, or http method fuzzing vulnerabilities', async () => {
      await runner
        .createScan({
          tests: [
            'excessive_data_exposure',
            TestType.SQLI,
            TestType.XSS,
            TestType.HTTP_METHOD_FUZZING
          ],
          attackParamLocations: ['query']
        })
        .threshold('MEDIUM')
        .timeout(300000)
        .run({
          method: 'GET',
          url: `${baseUrl}/articles`,
          query: {
            tag: 'string',
            author: 'string',
            favorited: 'string',
            limit: '20',
            offset: '0'
          }
        });
    });
  });

  describe('GET /articles/{slug}', () => {
    it('should perform security tests', async () => {
      await runner
        .createScan({
          tests: [
            'broken_access_control',
            TestType.ID_ENUMERATION,
            'excessive_data_exposure'
          ],
          attackParamLocations: [
            // Specify attack parameter locations if needed
          ]
        })
        .threshold(Severity.MEDIUM)
        .timeout(300000) // 5 minutes
        .run({
          method: 'GET',
          url: `${baseUrl}/articles/{slug}`
        });
    });
  });

  describe('PUT /articles/{slug}', () => {
    it('should pass security tests', async () => {
      await runner
        .createScan({
          tests: [TestType.JWT, TestType.CSRF, TestType.MASS_ASSIGNMENT, TestType.XSS, TestType.SQLI],
          attackParamLocations: ['body', 'query', 'headers']
        })
        .threshold('MEDIUM')
        .timeout(300000) // 5 minutes
        .run({
          method: 'PUT',
          url: `${baseUrl}/articles/{slug}`,
          headers: {
            'Authorization': 'Token jwt.token.here'
          },
          body: {
            mimeType: 'application/json',
            text: JSON.stringify({
              article: {
                title: 'string',
                description: 'string',
                body: 'string'
              }
            })
          }
        });
    });
  });
});
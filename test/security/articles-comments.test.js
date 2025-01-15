import { SecRunner } from '@sectester/runner';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('POST /articles/example-article/comments', () => {
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

  it('should pass security tests', async () => {
    await runner
      .createScan({
        tests: [
          TestType.CSRF,
          TestType.JWT,
          TestType.XSS,
          TestType.SQLI,
          'excessive_data_exposure',
          'broken_access_control'
        ],
        attackParamLocations: [
          AttackParamLocation.BODY,
          AttackParamLocation.HEADER
        ]
      })
      .threshold(Severity.MEDIUM)
      .timeout(300000) // 5 minutes
      .run({
        method: 'POST',
        url: `${baseUrl}/articles/example-article/comments`,
        headers: {
          Authorization: 'Bearer <token>',
          'Content-Type': 'application/json'
        },
        body: {
          comment: {
            body: 'This is a comment.'
          }
        }
      });
  });
});
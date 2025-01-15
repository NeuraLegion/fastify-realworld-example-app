import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('GET /articles/example-article/comments', () => {
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
          TestType.BROKEN_ACCESS_CONTROL,
          TestType.CSRF,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.JWT
        ]
      })
      .threshold(Severity.MEDIUM)
      .timeout(300000) // 5 minutes
      .run({
        method: 'GET',
        url: `${baseUrl}/articles/example-article/comments`,
        headers: {
          Authorization: 'Bearer <token>'
        }
      });
  });
});
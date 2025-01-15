import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('/sentiment', () => {
  let runner;
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

  it('POST /score', async () => {
    await runner
      .createScan({
        tests: [TestType.CSRF, 'excessive_data_exposure', TestType.INSECURE_OUTPUT_HANDLING, TestType.XSS],
        attackParamLocations: ['body']
      })
      .threshold('MEDIUM')
      .timeout(300000)
      .run({
        method: 'POST',
        url: `${baseUrl}/sentiment/score`,
        body: { content: 'string' }
      });
  });
});
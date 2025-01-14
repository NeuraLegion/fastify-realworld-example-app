import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

describe('/tags', () => {
  let runner!: SecRunner;
  const timeout = 300000;

  beforeAll(async () => {
    runner = new SecRunner({ hostname: 'app.neuralegion.com' });
    await runner.init();
  });

  afterAll(async () => {
    await runner.clear();
  });

  it('should not have excessive data exposure or insecure HTTP methods', async () => {
    await runner
      .createScan({
        tests: ['excessive_data_exposure', TestType.HTTP_METHOD_FUZZING]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: 'http://localhost:3000/tags'
      });
  });
});
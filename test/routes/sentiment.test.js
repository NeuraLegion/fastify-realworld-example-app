import { SecRunner, SecScan } from '@sectester/runner';
import { Severity, TestType } from '@sectester/scan';

describe('/sentiment/score', () => {
  let runner;
  let scan;

  beforeEach(async () => {
    runner = new SecRunner({ hostname: 'app.neuralegion.com' });
    await runner.init();
    scan = runner
      .createScan({ tests: [TestType.CSRF, TestType.XSS, TestType.SQLI, 'excessive_data_exposure', 'insecure_output_handling'] })
      .threshold(Severity.MEDIUM)
      .timeout(300000); // 5 minutes
  });

  afterEach(async () => {
    await runner.clear();
  });

  it('should pass security tests', async () => {
    await scan.run({
      method: 'POST',
      url: 'https://localhost:8000/sentiment/score',
      headers: { 'Content-Type': 'application/json' },
      body: { content: 'string' }
    });
  });
});
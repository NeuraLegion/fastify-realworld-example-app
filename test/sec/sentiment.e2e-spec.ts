import { SecRunner, SecScan } from '@sectester/runner';
import { TestType } from '@sectester/scan';
import { describe, it, beforeEach, afterEach } from 'tap';
import startServer from '../setup-server';

let runner: SecRunner;
let scan: SecScan;
let server: any;

const baseUrl = 'http://localhost:3000';

beforeEach(async () => {
  runner = new SecRunner({ hostname: 'app.brightsec.com' });
  await runner.init();
  server = await startServer();
  await server.listen(3000);
});

afterEach(async () => {
  await runner.clear();
  await server.close();
});

describe('/sentiment/score', () => {
  it('should not have CSRF', async () => {
    scan = runner.createScan({ tests: [TestType.CSRF] });
    await scan.run({
      method: 'POST',
      url: `${baseUrl}/sentiment/score`,
      headers: { 'Content-Type': 'application/json' },
      body: { content: 'string' }
    });
  });

  it('should not have XSS', async () => {
    scan = runner.createScan({ tests: [TestType.XSS] });
    await scan.run({
      method: 'POST',
      url: `${baseUrl}/sentiment/score`,
      headers: { 'Content-Type': 'application/json' },
      body: { content: 'string' }
    });
  });

  it('should not have SQLi', async () => {
    scan = runner.createScan({ tests: [TestType.SQLI] });
    await scan.run({
      method: 'POST',
      url: `${baseUrl}/sentiment/score`,
      headers: { 'Content-Type': 'application/json' },
      body: { content: 'string' }
    });
  });

  it('should not have excessive data exposure', async () => {
    scan = runner.createScan({ tests: ['excessive_data_exposure'] });
    await scan.run({
      method: 'POST',
      url: `${baseUrl}/sentiment/score`,
      headers: { 'Content-Type': 'application/json' },
      body: { content: 'string' }
    });
  });

  it('should not have insecure output handling', async () => {
    scan = runner.createScan({ tests: ['insecure_output_handling'] });
    await scan.run({
      method: 'POST',
      url: `${baseUrl}/sentiment/score`,
      headers: { 'Content-Type': 'application/json' },
      body: { content: 'string' }
    });
  });
});

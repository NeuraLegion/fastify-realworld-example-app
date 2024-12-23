import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';
import { describe, it, beforeEach, afterEach } from 'mocha';
import { expect } from 'chai';
import startServer from '../setup-server';

let runner: SecRunner;
let server: any;

beforeEach(async () => {
  runner = new SecRunner({ hostname: 'app.brightsec.com' });
  await runner.init();
  server = await startServer();
});

afterEach(async () => {
  await runner.clear();
  await server.close();
});

describe('GET /tags', () => {
  it('should not have XSS', async () => {
    const scan = runner.createScan({ tests: [TestType.XSS] });
    const response = await server.inject({
      method: 'GET',
      url: '/api/tags'
    });

    await scan.run({
      method: 'GET',
      url: 'http://localhost:3000/tags'
    });

    expect(response.statusCode).to.equal(200);
    expect(JSON.parse(response.body).tags).to.be.an('array');
  });
});

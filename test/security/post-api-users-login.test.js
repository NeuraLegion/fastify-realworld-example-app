const t = require('tap');
const startServer = require('../setup-server');
const { SecRunner } = require('@sectester/runner');
const { Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan');

let app;
let baseUrl;
let runner;

t.before(async () => {
  app = await startServer();
  baseUrl = await app.listen({ port: 0 });

  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
    projectId: process.env.BRIGHT_PROJECT_ID
  });

  await runner.init();
});

t.teardown(async () => {
  await runner.clear();
  await app.close();
});

// Test cases will be added here

t.test('POST /api/users/login', async t => {
  t.setTimeout(40 * 60 * 1000);

  const promise = runner
    .createScan({
      tests: ['csrf', 'excessive_data_exposure', 'jwt', 'mass_assignment', 'sqli'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.CRITICAL)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/users/login`,
      headers: { 'Content-Type': 'application/json' },
      body: { user: { email: 'example@example.com', password: 'password123' } }
    });

  await t.resolves(promise);
});

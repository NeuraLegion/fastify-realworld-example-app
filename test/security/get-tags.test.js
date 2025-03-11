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

// Teardown logic

t.teardown(async () => {
  await runner.clear();
  await app.close();
});

// Test case for GET /tags

t.test('GET /tags', async t => {
  t.setTimeout(40 * 60 * 1000);

  const promise = runner
    .createScan({
      tests: ['excessive_data_exposure', 'sqli', 'csrf', 'xss'],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/tags`
    });

  await t.resolves(promise);
});

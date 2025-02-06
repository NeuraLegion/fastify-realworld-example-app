const t = require('tap');
const { SecRunner } = require('@sectester/runner');
const { TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan');

let runner;
let app;
let baseUrl;

// Setup hooks for starting and stopping the application

t.before(async () => {
  app = await require('../../lib/server')(); // Adjust the path as necessary
  baseUrl = await app.listen({ port: 0 });
});

t.teardown(() => app.close());

// Setup hooks for initializing and clearing SecTester

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });
  await runner.init();
});

t.afterEach(() => runner.clear());

// Placeholder for actual test cases

t.test('GET /api/articles', async t => {
  const promise = runner
    .createScan({
      tests: [TestType.SQLI, TestType.XSS, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.ID_ENUMERATION],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/api/articles`,
      query: {
        tag: 'string',
        author: 'string',
        favorited: 'string',
        limit: '20',
        offset: '0'
      }
    });

  t.rejects(promise);
  t.end();
});

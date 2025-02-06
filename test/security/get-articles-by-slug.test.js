const t = require('tap');
const { SecRunner } = require('@sectester/runner');
const startServer = require('../setup-server');

let runner;
let app;
let baseUrl;

// Setup hooks for initializing the application and SecTester

t.before(async () => {
  app = await startServer();

  await app.ready();

  baseUrl = app.server.address().port;
});

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });

  await runner.init();
});

t.afterEach(() => runner.clear());

t.after(() => app.close());

// Placeholder for test cases

test('GET /api/articles/:slug', async t => {
  const promise = runner
    .createScan({
      tests: [
        'sqli',
        'xss',
        'excessive_data_exposure',
        'id_enumeration',
        'full_path_disclosure'
      ],
      attackParamLocations: ['path']
    })
    .threshold('low')
    .timeout(15 * 60 * 1000)
    .run({
      method: 'GET',
      url: `${baseUrl}/api/articles/test-slug`
    });

  await t.notThrowsAsync(promise);
});

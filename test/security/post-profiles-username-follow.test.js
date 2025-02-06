const t = require('tap');
const { SecRunner } = require('@sectester/runner');
const start = require('../setup-server');

let runner;
let app;
let baseUrl;

// Setup hooks for initializing the application and SecTester

t.before(async () => {
  app = await start();

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

test('POST /api/profiles/:username/follow', async t => {
  const promise = runner
    .createScan({
      tests: [
        'sqli',
        'xss',
        'csrf',
        'broken_access_control',
        'insecure_output_handling',
        'mass_assignment',
        'excessive_data_exposure',
        'jwt',
        'cookie_security',
        'brute_force_login',
        'stored_xss',
        'unvalidated_redirect'
      ],
      attackParamLocations: ['body', 'header', 'path']
    })
    .threshold('LOW')
    .timeout(15 * 60 * 1000)
    .run({
      method: 'POST',
      url: `${baseUrl}/api/profiles/:username/follow`,
      headers: { Authorization: 'Token jwt.token.here' }
    });

  await t.notThrowsAsync(promise);
});

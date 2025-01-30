const t = require('tap');
const startServer = require('../setup-server');
const { SecRunner } = require('@sectester/runner');
const { TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan');

let runner;
let app;
let baseUrl;

t.before(async () => {
  app = await startServer();
  await app.ready();

  const address = app.server.address();
  const protocol = app.server instanceof https.Server ? 'https' : 'http';
  baseUrl = `${protocol}://localhost:${address.port}`;
});

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });

  await runner.init();
});

t.afterEach(() => runner.clear());
t.after(() => app.close());

test('POST /api/articles/sample-article/comments', async t => {
  const promise = runner
    .createScan({
      tests: [
        TestType.SQLI,
        TestType.XSS,
        TestType.CSRF,
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.MASS_ASSIGNMENT,
        TestType.STORED_XSS,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.ID_ENUMERATION,
        TestType.JWT
      ],
      attackParamLocations: [
        AttackParamLocation.BODY,
        AttackParamLocation.HEADER
      ]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/articles/sample-article/comments`,
      headers: {
        Authorization: 'Token sample.jwt.token'
      },
      body: {
        comment: {
          body: 'This is a sample comment.'
        }
      }
    });

  await t.notThrowsAsync(promise);
});

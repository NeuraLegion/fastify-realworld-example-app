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

test('PUT /articles/:slug', async t => {
  const promise = runner
    .createScan({
      tests: [
        TestType.SQLI,
        TestType.XSS,
        TestType.CSRF,
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.MASS_ASSIGNMENT,
        TestType.STORED_XSS
      ],
      attackParamLocations: [
        AttackParamLocation.PATH,
        AttackParamLocation.BODY,
        AttackParamLocation.HEADER
      ]
    })
    .threshold(Severity.LOW)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/articles/:slug`,
      headers: {
        Authorization: 'Token jwt.token.here'
      },
      body: {
        article: {
          title: 'string',
          description: 'string',
          body: 'string'
        }
      }
    });

  await t.notThrow(promise);
});

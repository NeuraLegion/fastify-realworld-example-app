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

test('PUT /api/user', async t => {
  const promise = runner
    .createScan({
      tests: [
        TestType.SQLI,
        TestType.XSS,
        TestType.CSRF,
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.MASS_ASSIGNMENT,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.ID_ENUMERATION,
        TestType.JWT,
        TestType.STORED_XSS,
        TestType.UNVALIDATED_REDIRECT,
        TestType.LFI,
        TestType.RFI,
        TestType.SSRF,
        TestType.SSTI,
        TestType.XXE,
        TestType.NOSQL,
        TestType.LDAPI,
        TestType.XPATHI,
        TestType.PROMPT_INJECTION,
        TestType.PROTO_POLLUTION,
        TestType.EMAIL_INJECTION,
        TestType.CSS_INJECTION,
        TestType.IFRAME_INJECTION,
        TestType.FULL_PATH_DISCLOSURE,
        TestType.IMPROPER_ASSET_MANAGEMENT,
        TestType.OPEN_CLOUD_STORAGE,
        TestType.OPEN_DATABASE,
        TestType.PASSWORD_RESET_POISONING,
        TestType.SECRET_TOKENS,
        TestType.HTTP_METHOD_FUZZING,
        TestType.BUSINESS_CONSTRAINT_BYPASS
      ],
      attackParamLocations: [
        AttackParamLocation.BODY,
        AttackParamLocation.HEADER
      ]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/user`,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer <token>'
      },
      body: {
        user: {
          email: 'updateduser@example.com',
          username: 'updateduser',
          password: 'newpassword123',
          bio: 'Updated bio',
          image: 'http://example.com/image.jpg'
        }
      }
    });

  await t.notThrowsAsync(promise);
});

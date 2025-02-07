const t = require('tap');
const { SecRunner } = require('@sectester/runner');
const { TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan');

let runner;
const baseUrl = process.env.BRIGHT_TARGET_URL || 'http://localhost:3000';

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });

  await runner.init();
});

t.afterEach(() => runner.clear());

t.test('GET /articles', async t => {
  t.setTimeout(15 * 60 * 1000);

  const promise = runner
    .createScan({
      tests: [
        TestType.SQLI,
        TestType.XSS,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.ID_ENUMERATION,
        TestType.HTTP_METHOD_FUZZING
      ],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/articles`,
      query: {
        tag: 'string',
        author: 'string',
        favorited: 'string',
        limit: '20',
        offset: '0'
      }
    });

  await t.resolves(promise);
});

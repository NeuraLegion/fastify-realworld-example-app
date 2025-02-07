const t = require('tap');
const { SecRunner } = require('@sectester/runner');
const startServer = require('../setup-server');

let runner;
let app;
let baseUrl;

t.before(async () => {
  app = await startServer();
  baseUrl = await app.listen({ port: 0 });
});

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });
  await runner.init();
});

t.afterEach(() => runner.clear());

t.teardown(() => app.close());

t.test('GET /articles', async t => {
  t.timeout(15 * 60 * 1000);

  const promise = runner
    .createScan({
      tests: ['sqli', 'xss', 'excessive_data_exposure', 'id_enumeration'],
      attackParamLocations: ['query']
    })
    .threshold('low')
    .timeout(15 * 60 * 1000)
    .run({
      method: 'GET',
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

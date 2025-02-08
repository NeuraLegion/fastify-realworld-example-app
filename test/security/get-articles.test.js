'use strict'
const t = require('tap')
const { SecRunner } = require('@sectester/runner')
const startServer = require('../../setup-server')

let runner;
let server;
let baseUrl;

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });
  await runner.init();

  server = await startServer();
  baseUrl = await server.listen({ port: 0 });
});

t.afterEach(async () => {
  await runner.clear();
  await server.close();
});

t.test('GET /articles', async t => {
  t.setTimeout(15 * 60 * 1000);

  const promise = runner
    .createScan({
      tests: [
        'sqli',
        'xss',
        'excessive_data_exposure',
        'id_enumeration'
      ],
      attackParamLocations: ['query']
    })
    .threshold('LOW')
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

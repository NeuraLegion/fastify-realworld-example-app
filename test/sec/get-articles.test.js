'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner


t.test('setup', async t => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()
  t.end()
})

t.teardown(async () => {
  await runner.clear()
})


// Test cases will be added here

t.test('GET /api/articles', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.SQLI, TestType.XSS, 'excessive_data_exposure', 'csrf', 'http_method_fuzzing'],
    attackParamLocations: ['query']
  })
  .threshold('medium')
  .timeout(60000)
  .run({
    method: 'GET',
    url: '/api/articles',
    query: {
      tag: 'string',
      author: 'string',
      favorited: 'string',
      limit: 10,
      offset: 0
    }
  })

  t.end()
})

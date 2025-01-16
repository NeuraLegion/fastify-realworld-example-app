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


// Test cases

t.test('GET /tags security tests', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.ExcessiveDataExposure, TestType.HttpMethodFuzzing, 'id_enumeration'],
    attackParamLocations: ['QUERY', 'BODY', 'HEADER']
  })
  .threshold('MEDIUM')
  .timeout(60000)
  .run({
    method: 'GET',
    url: `${server.baseUrl}/tags`
  })

  t.end()
})

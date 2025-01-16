'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

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

t.test('GET /api/articles/feed', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, 'EXCESSIVE_DATA_EXPOSURE', TestType.HTTP_METHOD_FUZZING, 'ID_ENUMERATION'],
    attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.QUERY]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000) // 15 minutes
  .run({
    method: 'GET',
    url: `${server.baseUrl}/api/articles/feed`,
    headers: { 'Authorization': 'Token jwt.token.here' },
    query: { limit: 'number', offset: 'number' }
  })

  t.end()
})

'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('GET /api/articles/feed', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()

  t.teardown(() => runner.clear())

  await runner.createScan({
    tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, TestType.EXCESSIVE_DATA_EXPOSURE, 'HTTP_METHOD_FUZZING'],
    attackParamLocations: [AttackParamLocation.QUERY]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'GET',
    url: `${server.baseUrl}/api/articles/feed`,
    headers: { 'Authorization': 'Token jwt.token.here' },
    query: { limit: 'integer', offset: 'integer' }
  })

  t.end()
})
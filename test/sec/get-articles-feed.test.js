'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for GET /articles/feed', async t => {
  let server

  t.beforeEach(async () => {
    server = await startServer()
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.teardown(async () => {
    await runner.clear()
    await server.close()
  })

  t.test('GET /articles/feed', async t => {
    await runner.createScan({
      tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, TestType.EXCESSIVE_DATA_EXPOSURE, 'HTTP_METHOD_FUZZING', 'ID_ENUMERATION'],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: 'GET',
      url: `${server.baseUrl}/articles/feed`,
      headers: { 'Authorization': 'Token jwt.token.here' },
      query: { limit: 'integer', offset: 'integer' }
    })

    t.end()
  })

  t.end()
})

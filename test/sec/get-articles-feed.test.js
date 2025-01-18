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
      tests: [TestType.JWT, 'excessive_data_exposure', 'broken_access_control', TestType.HTTP_METHOD_FUZZING],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: 'GET',
      url: '/articles/feed',
      headers: { 'Authorization': 'Token jwt.token.here' },
      queryString: { limit: 'number', offset: 'number' }
    })

    t.end()
  })

  t.end()
})

'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for GET /api/tags', async t => {
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

  t.test('Excessive Data Exposure and HTTP Method Fuzzing', async t => {
    await runner.createScan({
      tests: [TestType.EXCESSIVE_DATA_EXPOSURE, 'HTTP_METHOD_FUZZING'],
      attackParamLocations: []
    })
    .threshold('MEDIUM')
    .timeout(15 * 60 * 1000)
    .run({
      method: 'GET',
      url: `${server.baseUrl}/api/tags`
    })

    t.end()
  })

  t.end()
})

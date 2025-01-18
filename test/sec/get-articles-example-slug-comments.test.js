'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for GET /articles/example-slug/comments', async t => {
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

  t.test('GET /articles/example-slug/comments', async t => {
    await runner
      .createScan({
        tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, 'excessive_data_exposure'],
        attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH]
      })
      .threshold(Severity.MEDIUM)
      .timeout(15 * 60 * 1000)
      .run({
        method: 'GET',
        url: `${server.baseUrl}/articles/example-slug/comments`,
        headers: {
          Authorization: 'Token optional-jwt-token'
        }
      })
    t.end()
  })

  t.end()
})

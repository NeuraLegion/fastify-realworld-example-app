'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

// Set the timeout for the tests
jest.setTimeout(testTimeout)

t.test('GET /articles/example-article/comments', async t => {
  let server
  let baseUrl

  t.before(async () => {
    server = await startServer()
    const address = server.server.address()
    baseUrl = `http://localhost:${address.port}`
  })

  t.teardown(() => server.close())

  t.beforeEach(async () => {
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.afterEach(() => runner.clear())

  t.test('Security tests for GET /articles/example-article/comments', async t => {
    await runner.createScan({
      tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, 'EXCESSIVE_DATA_EXPOSURE'],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.QUERY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(testTimeout)
    .run({
      method: 'GET',
      url: `${baseUrl}/articles/example-article/comments`,
      headers: {
        'Authorization': 'Bearer <token>'
      }
    })
    t.end()
  })

  t.end()
})

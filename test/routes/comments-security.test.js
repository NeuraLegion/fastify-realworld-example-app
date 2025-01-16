'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for DELETE /api/articles/sample-article/comments/1', async t => {
  t.timeout(testTimeout)

  const server = await startServer()
  t.teardown(() => server.close())

  t.beforeEach(async () => {
    runner = new SecRunner({
      /* config */
    })
    await runner.init()
  })

  t.afterEach(async () => {
    await runner.clear()
  })

  await runner.createScan({
    tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, 'id_enumeration'],
    attackParamLocations: [AttackParamLocation.PATH]
  })
  .threshold(Severity.MEDIUM)
  .timeout(testTimeout)
  .run({
    method: 'DELETE',
    url: 'http://example.com/api/articles/sample-article/comments/1',
    headers: {
      'Authorization': 'Token required_jwt_token'
    }
  })

  t.end()
})

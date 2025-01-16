'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for /articles/feed', async t => {
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

  t.test('GET /articles/feed', async t => {
    await runner.createScan({
      tests: [
        TestType.JWT,
        TestType.BROKEN_ACCESS_CONTROL,
        'EXCESSIVE_DATA_EXPOSURE',
        TestType.HTTP_METHOD_FUZZING,
        'ID_ENUMERATION'
      ],
      attackParamLocations: [
        AttackParamLocation.QUERY,
        AttackParamLocation.HEADER
      ]
    })
    .threshold(Severity.MEDIUM)
    .timeout(testTimeout)
    .run({
      method: 'GET',
      url: '/articles/feed',
      headers: {
        Authorization: 'Token jwt.token.here'
      },
      query: {
        limit: 'number',
        offset: 'number'
      }
    })

    t.end()
  })

  t.end()
})

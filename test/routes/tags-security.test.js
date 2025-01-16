'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for /tags endpoint', async t => {
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

  t.test('GET /tags - excessive data exposure', async t => {
    await runner.createScan({
      tests: ['excessive_data_exposure'],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(testTimeout)
    .run({
      method: 'GET',
      url: 'http://localhost:3000/tags'
    })

    t.end()
  })

  t.test('GET /tags - HTTP method fuzzing', async t => {
    await runner.createScan({
      tests: [TestType.HTTP_METHOD_FUZZING],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(testTimeout)
    .run({
      method: 'GET',
      url: 'http://localhost:3000/tags'
    })

    t.end()
  })

  t.end()
})

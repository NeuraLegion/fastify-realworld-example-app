'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for /sentiment/score', async t => {
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

  t.test('POST /sentiment/score', async t => {
    await runner.createScan({
      tests: [TestType.CSRF, 'insecure_output_handling', 'excessive_data_exposure'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(testTimeout)
    .run({
      method: 'POST',
      url: '/sentiment/score',
      body: {
        mimeType: 'application/json',
        text: JSON.stringify({ content: 'Sample text to analyze sentiment.' })
      }
    })

    t.end()
  })

  t.end()
})

'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for GET /articles/:slug', async t => {
  t.beforeEach(async () => {
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.teardown(async () => {
    await runner.clear()
  })

  t.test('initialize server', async t => {
    const server = await startServer()
    t.teardown(() => server.close())

    t.test('GET /articles/:slug', async t => {
      await runner.createScan({
        tests: [
          'excessive_data_exposure',
          'id_enumeration',
          'insecure_output_handling',
          TestType.XSS
        ],
        attackParamLocations: ['PATH']
      })
      .threshold('MEDIUM')
      .timeout(TEST_TIMEOUT)
      .run({
        method: 'GET',
        url: `${server.baseUrl}/articles/test-slug`
      })

      t.end()
    })

    t.end()
  })

  t.end()
})

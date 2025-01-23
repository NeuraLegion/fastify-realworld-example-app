'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for GET /articles', async t => {
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

    await runner.createScan({
      tests: [
        'excessive_data_exposure',
        'id_enumeration',
        TestType.SQLI,
        TestType.XSS,
        TestType.CSRF,
        'http_method_fuzzing'
      ],
      attackParamLocations: ['query']
    }).run({
      method: 'GET',
      url: '/api/articles'
    })

    t.end()
  })

  t.end()
})

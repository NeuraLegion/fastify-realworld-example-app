'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, Severity, HttpMethod, AttackParamLocation } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('security tests for POST /sentiment/score', async t => {
  let server
  t.before(async () => {
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

  t.test('POST /sentiment/score', async t => {
    await runner.createScan({
      tests: [
        TestType.JWT,
        TestType.CSRF,
        TestType.SQLI,
        TestType.XSS,
        'INSECURE_OUTPUT_HANDLING',
        'EXCESSIVE_DATA_EXPOSURE'
      ],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: '/sentiment/score',
      headers: {
        Authorization: 'Bearer <token>'
      },
      body: {
        content: '<string>'
      }
    })

    t.end()
  })

  t.end()
})
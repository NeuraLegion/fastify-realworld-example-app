'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('security tests for GET /articles', async t => {
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

  t.test('GET /articles', async t => {
    await runner.createScan({
      tests: [
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.SQLI,
        TestType.XSS,
        TestType.CSRF,
        TestType.ID_ENUMERATION,
        'http_method_fuzzing'
      ],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${server.baseUrl}/articles`
    })

    t.end()
  })

  t.end()
})
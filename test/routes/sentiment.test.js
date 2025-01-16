'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('SecTester integration for /sentiment/score', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  t.beforeEach(async () => {
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.afterEach(() => runner.clear())

  t.test('POST /sentiment/score security tests', async t => {
    await runner.createScan({
      tests: [TestType.JWT, TestType.CSRF, TestType.XSS, TestType.SQLI, 'excessive_data_exposure'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: 'POST',
      url: `${server.baseUrl}/sentiment/score`,
      headers: { 'Authorization': 'Bearer <token>' },
      body: { 'content': '<string>' }
    })

    t.end()
  })

  t.end()
})
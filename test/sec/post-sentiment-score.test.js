'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('POST /sentiment/score security tests', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()

  t.teardown(() => runner.clear())

  await runner.createScan({
    tests: [
      TestType.CSRF,
      TestType.XSS,
      TestType.SQLI,
      'EXCESSIVE_DATA_EXPOSURE',
      'INSECURE_OUTPUT_HANDLING'
    ],
    attackParamLocations: [AttackParamLocation.BODY]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'POST',
    url: `${server.baseUrl}/sentiment/score`,
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      content: 'string'
    })
  })

  t.end()
})
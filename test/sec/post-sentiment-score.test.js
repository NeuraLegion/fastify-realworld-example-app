'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner


t.test('setup', async t => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()
  t.end()
})

t.teardown(async () => {
  await runner.clear()
})

t.test('POST /sentiment/score', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [
      TestType.CSRF,
      'JSON_INJECTION',
      TestType.EDO,
      'INSECURE_OUTPUT_HANDLING'
    ],
    attackParamLocations: [AttackParamLocation.BODY]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000) // 15 minutes
  .run({
    method: 'POST',
    url: `${server.baseUrl}/sentiment/score`,
    body: JSON.stringify({ content: 'string' }),
    headers: { 'Content-Type': 'application/json' }
  })

  t.end()
})

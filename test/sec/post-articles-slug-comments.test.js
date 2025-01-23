'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('POST /articles/:slug/comments', async t => {
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

  await runner.createScan({
    tests: [
      TestType.JWT,
      TestType.CSRF,
      TestType.XSS,
      TestType.STORED_XSS,
      TestType.SQLI,
      TestType.BROKEN_ACCESS_CONTROL,
      TestType.EXCESSIVE_DATA_EXPOSURE,
      TestType.INSECURE_OUTPUT_HANDLING
    ],
    attackParamLocations: [AttackParamLocation.BODY]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: HttpMethod.POST,
    url: `${server.baseUrl}/articles/some-slug/comments`,
    headers: {
      'Authorization': 'Token jwt.token.here',
      'Content-Type': 'application/json'
    },
    body: {
      comment: {
        body: 'string'
      }
    }
  })

  t.end()
})
'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, Severity, HttpMethod, AttackParamLocation } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('security tests for POST /api/articles/example-article/comments', async t => {
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

  t.test('POST /api/articles/example-article/comments', async t => {
    await runner.createScan({
      tests: [
        TestType.CSRF,
        TestType.XSS,
        TestType.STORED_XSS,
        TestType.SQLI,
        'insecure_output_handling',
        'broken_access_control'
      ],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: 'http://localhost:5000/api/articles/example-article/comments',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        comment: {
          body: 'This is a comment.'
        }
      })
    })

    t.end()
  })

  t.end()
})
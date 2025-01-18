'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for POST /articles/example-article/comments', async t => {
  let server

  t.beforeEach(async () => {
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

  t.test('POST /articles/example-article/comments', async t => {
    await runner.createScan({
      tests: [
        TestType.JWT,
        TestType.CSRF,
        TestType.XSS,
        TestType.SQLI,
        'excessive_data_exposure',
        'broken_access_control'
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: 'POST',
      url: 'http://localhost:3000/articles/example-article/comments',
      headers: {
        'Authorization': 'Token required_jwt_token',
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

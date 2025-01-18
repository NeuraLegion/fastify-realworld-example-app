'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for PUT /api/user', async t => {
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

  t.test('PUT /api/user', async t => {
    await runner.createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.CSRF,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.MASS_ASSIGNMENT,
        TestType.SQLI,
        TestType.XSS
      ],
      attackParamLocations: ['BODY', 'HEADER']
    })
    .threshold('MEDIUM')
    .timeout(15 * 60 * 1000)
    .run({
      method: 'PUT',
      url: 'http://localhost:3000/api/user',
      headers: {
        'Authorization': 'Bearer <token>',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user: {
          email: 'updated@example.com',
          password: 'newpassword123'
        }
      })
    })

    t.end()
  })

  t.end()
})

'use strict'
const t = require('tap')
const { SecRunner, TestType } = require('@sectester/runner')
const startServer = require('../setup-server')

const configuration = { hostname: 'app.brightsec.com' }

async function runSecurityTests() {
  const runner = new SecRunner(configuration)
  await runner.init()

  const scan = runner.createScan({
    tests: [
      'broken_access_control',
      'csrf',
      'id_enumeration'
    ]
  })

  const target = {
    method: 'DELETE',
    url: 'http://localhost:3000/api/articles/example-slug/comments/1',
    headers: { Authorization: 'Token required-auth-token' }
  }

  await scan.run(target)
  await runner.clear()
}

runSecurityTests().catch(err => {
  console.error('Security tests failed:', err)
})

module.exports = runSecurityTests

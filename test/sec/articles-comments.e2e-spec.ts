import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';
import { describe, it, beforeEach, afterEach } from 'mocha';
import { expect } from 'chai';

const configuration = { hostname: 'app.brightsec.com' };

let runner: SecRunner;

beforeEach(async () => {
  runner = new SecRunner(configuration);
  await runner.init();
});

afterEach(async () => {
  await runner.clear();
});

describe('POST /api/articles/example-slug/comments', () => {
  it('should not have CSRF', async () => {
    const scan = runner.createScan({
      tests: [TestType.CSRF],
      attackParamLocations: [AttackParamLocation.BODY]
    });

    const result = await scan.run({
      method: 'POST',
      url: 'http://localhost:3000/api/articles/example-slug/comments',
      headers: {
        'Authorization': 'Token required-auth-token',
        'Content-Type': 'application/json'
      },
      body: { comment: { body: 'This is a comment.' } }
    });

    expect(result).to.be.empty;
  });

  it('should not have XSS', async () => {
    const scan = runner.createScan({
      tests: [TestType.XSS],
      attackParamLocations: [AttackParamLocation.BODY]
    });

    const result = await scan.run({
      method: 'POST',
      url: 'http://localhost:3000/api/articles/example-slug/comments',
      headers: {
        'Authorization': 'Token required-auth-token',
        'Content-Type': 'application/json'
      },
      body: { comment: { body: 'This is a comment.' } }
    });

    expect(result).to.be.empty;
  });

  it('should not have SQLi', async () => {
    const scan = runner.createScan({
      tests: [TestType.SQLI],
      attackParamLocations: [AttackParamLocation.BODY]
    });

    const result = await scan.run({
      method: 'POST',
      url: 'http://localhost:3000/api/articles/example-slug/comments',
      headers: {
        'Authorization': 'Token required-auth-token',
        'Content-Type': 'application/json'
      },
      body: { comment: { body: 'This is a comment.' } }
    });

    expect(result).to.be.empty;
  });

  it('should not have broken access control', async () => {
    const scan = runner.createScan({
      tests: ['broken_access_control'],
      attackParamLocations: [AttackParamLocation.BODY]
    });

    const result = await scan.run({
      method: 'POST',
      url: 'http://localhost:3000/api/articles/example-slug/comments',
      headers: {
        'Authorization': 'Token required-auth-token',
        'Content-Type': 'application/json'
      },
      body: { comment: { body: 'This is a comment.' } }
    });

    expect(result).to.be.empty;
  });

  it('should not have excessive data exposure', async () => {
    const scan = runner.createScan({
      tests: ['excessive_data_exposure'],
      attackParamLocations: [AttackParamLocation.BODY]
    });

    const result = await scan.run({
      method: 'POST',
      url: 'http://localhost:3000/api/articles/example-slug/comments',
      headers: {
        'Authorization': 'Token required-auth-token',
        'Content-Type': 'application/json'
      },
      body: { comment: { body: 'This is a comment.' } }
    });

    expect(result).to.be.empty;
  });
});

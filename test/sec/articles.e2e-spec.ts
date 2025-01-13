import { SecRunner, SecScan } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';
import { describe, it, beforeEach, afterEach } from 'mocha';
import { expect } from 'chai';
import startServer from '../setup-server';

let runner: SecRunner;
let server: any;
let scan: SecScan;

const baseUrl = 'http://localhost:3000/api/articles';
const commentsUrl = `${baseUrl}/example-slug/comments`;

beforeEach(async () => {
  runner = new SecRunner({ hostname: 'app.brightsec.com' });
  await runner.init();
  server = await startServer();
});

afterEach(async () => {
  await runner.clear();
  await server.close();
});

describe('/articles', () => {
  it('should not have excessive data exposure', async () => {
    const scan = runner.createScan({
      tests: ['excessive_data_exposure'],
      attackParamLocations: [AttackParamLocation.QUERY]
    });

    const response = await scan.run({
      method: 'GET',
      url: baseUrl,
      query: {
        tag: 'test',
        author: 'test',
        favorited: 'test',
        limit: '20',
        offset: '0'
      }
    });

    expect(response).to.have.property('issues').that.is.empty;
  });

  it('should not have ID enumeration', async () => {
    const scan = runner.createScan({
      tests: [TestType.ID_ENUMERATION],
      attackParamLocations: [AttackParamLocation.QUERY]
    });

    const response = await scan.run({
      method: 'GET',
      url: baseUrl,
      query: {
        tag: 'test',
        author: 'test',
        favorited: 'test',
        limit: '20',
        offset: '0'
      }
    });

    expect(response).to.have.property('issues').that.is.empty;
  });

  it('should not have HTTP method fuzzing issues', async () => {
    const scan = runner.createScan({
      tests: [TestType.HTTP_METHOD_FUZZING],
      attackParamLocations: [AttackParamLocation.QUERY]
    });

    const response = await scan.run({
      method: 'GET',
      url: baseUrl,
      query: {
        tag: 'test',
        author: 'test',
        favorited: 'test',
        limit: '20',
        offset: '0'
      }
    });

    expect(response).to.have.property('issues').that.is.empty;
  });

  it('should not have SQL injection vulnerabilities', async () => {
    const scan = runner.createScan({
      tests: [TestType.SQLI],
      attackParamLocations: [AttackParamLocation.QUERY]
    });

    const response = await scan.run({
      method: 'GET',
      url: baseUrl,
      query: {
        tag: 'test',
        author: 'test',
        favorited: 'test',
        limit: '20',
        offset: '0'
      }
    });

    expect(response).to.have.property('issues').that.is.empty;
  });

  it('should not have XSS vulnerabilities', async () => {
    const scan = runner.createScan({
      tests: [TestType.XSS],
      attackParamLocations: [AttackParamLocation.QUERY]
    });

    const response = await scan.run({
      method: 'GET',
      url: baseUrl,
      query: {
        tag: 'test',
        author: 'test',
        favorited: 'test',
        limit: '20',
        offset: '0'
      }
    });

    expect(response).to.have.property('issues').that.is.empty;
  });
});

describe('API Security Tests for /api/articles/example-slug/comments', () => {
  beforeEach(async () => {
    scan = runner.createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.CSRF,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.HTTP_METHOD_FUZZING,
        TestType.ID_ENUMERATION,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.XSS
      ]
    });
  });

  it('should perform security tests on the endpoint', async () => {
    const result = await scan.run({
      method: 'GET',
      url: commentsUrl,
      headers: {
        Authorization: 'Token optional-auth-token'
      }
    });

    expect(result).to.be.an('object');
    expect(result.issues).to.be.an('array');
  });
});

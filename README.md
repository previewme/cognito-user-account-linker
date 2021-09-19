# cognito-user-account-linker

[![CI Workflow](https://github.com/previewme/cognito-user-account-linker/actions/workflows/ci.yml/badge.svg)](https://github.com/previewme/cognito-user-account-linker/actions/workflows/ci.yml)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=previewme_cognito-user-account-linker&metric=coverage)](https://sonarcloud.io/dashboard?id=previewme_cognito-user-account-linker)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=previewme_cognito-user-account-linker&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=previewme_cognito-user-account-linker)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=previewme_cognito-user-account-linker&metric=alert_status)](https://sonarcloud.io/dashboard?id=previewme_cognito-user-account-linker)

Lambda function which links duplicate accounts together. Duplicate accounts exist when a user uses another form of login with the same email address. E.g: Google and then Facebook social login.

## Build

To build the lambda function run the following.

```
npm install
npm run build
```

## Test

To run the tests.

```
npm test
```

## Package

The following will package the lambda function into a zip bundle to allow manual deployment.

```
zip -q -r dist/lambda.zip node_modules dist
```

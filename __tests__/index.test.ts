import { handler } from '../src';
import { PreSignUpTriggerEvent } from 'aws-lambda';
import { PreSignUpExternalProviderTriggerEvent } from 'aws-lambda/trigger/cognito-user-pool-trigger/pre-signup';

let mockListUsers = jest.fn();

let mockCreateUser = jest.fn();

const mockLinkUser = jest.fn(() => {
    return {
        promise: jest.fn(() => Promise.resolve())
    };
});

const mockSetUserPassword = jest.fn(() => {
    return {
        promise: jest.fn(() => Promise.resolve())
    };
});

jest.mock('aws-sdk', () => {
    return {
        CognitoIdentityServiceProvider: jest.fn(() => {
            return {
                listUsers: mockListUsers,
                adminLinkProviderForUser: mockLinkUser,
                adminCreateUser: mockCreateUser,
                adminSetUserPassword: mockSetUserPassword
            };
        })
    };
});

describe('AWS Cognito account linking', () => {
    const cognitoNativeEvent: PreSignUpTriggerEvent = {
        version: '1',
        region: 'eu-central-1',
        userPoolId: 'eu-central-1_7HPNLvT',
        userName: 'c8302f6d-4469-b31e-36ee6239e267',
        callerContext: {
            awsSdkVersion: 'aws-sdk-unknown-unknown',
            clientId: '741igvddli8mdl2v0bpsqc'
        },
        triggerSource: 'PreSignUp_SignUp',
        request: {
            userAttributes: {
                given_name: 'Test',
                family_name: 'User',
                email: 'test@gmail.com'
            },
            validationData: {},
            clientMetadata: {}
        },
        response: {
            autoConfirmUser: false,
            autoVerifyEmail: false,
            autoVerifyPhone: false
        }
    };

    const cognitoSocialLogin: PreSignUpExternalProviderTriggerEvent = {
        version: '1',
        region: 'eu-central-1',
        userPoolId: 'eu-central-1_7HLvRT',
        userName: 'Google_1147527301736',
        callerContext: {
            awsSdkVersion: 'aws-sdk-unknown-unknown',
            clientId: '741if0rmdidv0bpsqc'
        },
        triggerSource: 'PreSignUp_ExternalProvider',
        request: {
            userAttributes: {
                email_verified: 'false',
                'cognito:email_alias': '',
                'cognito:phone_number_alias': '',
                given_name: 'test',
                family_name: 'user',
                email: 'test@gmail.com'
            },
            validationData: {}
        },
        response: {
            autoConfirmUser: false,
            autoVerifyEmail: false,
            autoVerifyPhone: false
        }
    };

    beforeEach(() => {
        jest.clearAllMocks();
        jest.clearAllTimers();
        mockListUsers = jest.fn(() => {
            return {
                promise: jest.fn(() =>
                    Promise.resolve({
                        Users: [
                            {
                                Username: 'test@gmail.com'
                            }
                        ]
                    })
                )
            };
        });

        mockCreateUser = jest.fn(() => {
            return {
                promise: jest.fn(() => Promise.resolve({ User: { Username: 'a33faa43-4430-46b9-9604-54f42bd12d51' } }))
            };
        });
    });

    test('Not a external provider login', async () => {
        const result = await handler(cognitoNativeEvent);
        expect(result).toEqual(cognitoNativeEvent);
    });

    test('External provider login with existing cognito native user', async () => {
        const result = await handler(cognitoSocialLogin);
        expect(result).toEqual(cognitoSocialLogin);

        expect(mockLinkUser).toHaveBeenCalledWith({
            DestinationUser: {
                ProviderAttributeValue: 'test@gmail.com',
                ProviderName: 'Cognito'
            },
            SourceUser: {
                ProviderAttributeName: 'Cognito_Subject',
                ProviderAttributeValue: '1147527301736',
                ProviderName: 'Google'
            },
            UserPoolId: 'eu-central-1_7HLvRT'
        });
        expect(mockLinkUser).toBeCalledTimes(1);
        expect(mockListUsers).toBeCalledTimes(1);
    });

    test('No username for existing cognito user', async () => {
        mockListUsers = jest.fn(() => {
            return {
                promise: jest.fn(() =>
                    Promise.resolve({
                        Users: [{}]
                    })
                )
            };
        });

        await expect(handler(cognitoSocialLogin)).rejects.toThrowError('Username not found');
    });

    test('No native cognito user when using social login', async () => {
        mockListUsers = jest.fn(() => {
            return {
                promise: jest.fn(() => Promise.resolve({}))
            };
        });
        await handler(cognitoSocialLogin);
        expect(mockLinkUser).toHaveBeenCalledWith({
            DestinationUser: {
                ProviderAttributeValue: 'a33faa43-4430-46b9-9604-54f42bd12d51',
                ProviderName: 'Cognito'
            },
            SourceUser: {
                ProviderAttributeName: 'Cognito_Subject',
                ProviderAttributeValue: '1147527301736',
                ProviderName: 'Google'
            },
            UserPoolId: 'eu-central-1_7HLvRT'
        });
        expect(mockSetUserPassword).toHaveBeenCalledWith(
            expect.objectContaining({
                UserPoolId: 'eu-central-1_7HLvRT',
                Username: 'test@gmail.com',
                Permanent: true,
                Password: expect.any(String)
            })
        );
        expect(mockLinkUser).toBeCalledTimes(1);
        expect(mockSetUserPassword).toBeCalledTimes(1);
        expect(mockListUsers).toBeCalledTimes(1);
    });

    test('No username when creating user', async () => {
        mockListUsers = jest.fn(() => {
            return {
                promise: jest.fn(() => Promise.resolve({}))
            };
        });

        mockCreateUser = jest.fn(() => {
            return {
                promise: jest.fn(() => Promise.resolve({}))
            };
        });

        await expect(handler(cognitoSocialLogin)).rejects.toThrowError('Username not found');
    });
});

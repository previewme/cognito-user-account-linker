import { PreSignUpTriggerEvent } from 'aws-lambda';
import AWS, { CognitoIdentityServiceProvider } from 'aws-sdk';
import { AdminCreateUserResponse, ListUsersResponse } from 'aws-sdk/clients/cognitoidentityserviceprovider';
import { generate } from 'generate-password';

const EXTERNAL_AUTHENTICATION_PROVIDER = 'PreSignUp_ExternalProvider';

async function getUsersByEmail(userPoolId: string, email: string, client: CognitoIdentityServiceProvider): Promise<ListUsersResponse> {
    return client.listUsers({ UserPoolId: userPoolId, Filter: `email = "${email}"` }).promise();
}

async function linkUserAccounts(
    cognitoUsername: string,
    userPoolId: string,
    providerName: string,
    providerUserId: string,
    client: CognitoIdentityServiceProvider
) {
    const params = {
        DestinationUser: {
            ProviderAttributeValue: cognitoUsername,
            ProviderName: 'Cognito'
        },
        SourceUser: {
            ProviderAttributeName: 'Cognito_Subject',
            ProviderAttributeValue: providerUserId,
            ProviderName: providerName
        },
        UserPoolId: userPoolId
    };
    await client.adminLinkProviderForUser(params).promise();
}

async function createUser(userPoolId: string, email: string, client: CognitoIdentityServiceProvider): Promise<AdminCreateUserResponse> {
    return await client
        .adminCreateUser({
            UserPoolId: userPoolId,
            MessageAction: 'SUPPRESS',
            Username: email,
            UserAttributes: [
                { Name: 'email', Value: email },
                { Name: 'email_verified', Value: 'true' }
            ]
        })
        .promise();
}

async function setUserPassword(userPoolId: string, email: string, client: CognitoIdentityServiceProvider) {
    await client
        .adminSetUserPassword({
            UserPoolId: userPoolId,
            Username: email,
            Password: generate({ length: 32, numbers: true, symbols: true }),
            Permanent: true
        })
        .promise();
}

export async function handler(event: PreSignUpTriggerEvent): Promise<PreSignUpTriggerEvent> {
    const client = new CognitoIdentityServiceProvider({ region: event.region });
    const email = event.request.userAttributes.email;
    const userPoolId = event.userPoolId;
    if (event.triggerSource == EXTERNAL_AUTHENTICATION_PROVIDER) {
        const usersFilteredByEmail = await getUsersByEmail(userPoolId, email, client);
        const [providerNameValue, providerUserId] = event.userName.split('_');
        const providerName = providerNameValue.charAt(0).toUpperCase() + providerNameValue.slice(1);

        if (usersFilteredByEmail.Users && usersFilteredByEmail.Users.length > 0) {
            const cognitoUsername = usersFilteredByEmail.Users[0].Username;
            if (cognitoUsername === undefined) {
                throw Error('Username not found');
            }
            await linkUserAccounts(cognitoUsername, userPoolId, providerName, providerUserId, client);
        } else {
            const newCognitoUser = await createUser(userPoolId, email, client);
            await setUserPassword(userPoolId, email, client);

            const cognitoNativeUsername = newCognitoUser.User?.Username;
            if (cognitoNativeUsername === undefined) {
                throw Error('Username not found');
            }
            const sns = new AWS.SNS();
            sns.publish(
                {
                    Message: 'Test publish to SNS from Lambda',
                    TopicArn: 'arn:aws:sns:us-east-1:371032233725:user-signup'
                },
                function (err) {
                    if (err) {
                        console.error('error publishing to SNS');
                    } else {
                        console.info('message published to SNS');
                    }
                }
            );
            // await linkUserAccounts(cognitoNativeUsername, userPoolId, providerName, providerUserId, client);
            // event.response.autoVerifyEmail = true;
            // event.response.autoConfirmUser = true;
        }
    }
    return event;
}

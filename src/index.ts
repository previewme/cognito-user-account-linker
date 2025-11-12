import { PreSignUpTriggerEvent } from 'aws-lambda';
import { CognitoIdentityServiceProvider } from 'aws-sdk';
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
    // eslint-disable-next-line no-console
    console.log('dx:providerName: ', providerName, providerUserId);
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
    // eslint-disable-next-line no-console
    console.log('dx:params: ', params);
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
    // eslint-disable-next-line no-console
    console.log('dx:event: ', event);
    const client = new CognitoIdentityServiceProvider({ region: event.region });
    const email = event.request.userAttributes.email;
    const userPoolId = event.userPoolId;

    // Extract provider info from event.userName
    const [providerNameValue, providerUserId] = event.userName.split('_');

    const providerMap: Record<string, string> = {
        google: 'Google',
        facebook: 'Facebook',
        linkedin: 'LinkedIn'
    };
    const providerName = providerMap[providerNameValue.toLowerCase()] || providerNameValue.charAt(0).toUpperCase() + providerNameValue.slice(1);

    // eslint-disable-next-line no-console
    console.log('PreSignUp triggered:', { providerName, providerUserId, email });

    if (event.triggerSource == EXTERNAL_AUTHENTICATION_PROVIDER) {
        const usersFilteredByEmail = await getUsersByEmail(userPoolId, email, client);

        if (usersFilteredByEmail.Users && usersFilteredByEmail.Users.length > 0) {
            const cognitoUsername = usersFilteredByEmail.Users[0].Username;
            // eslint-disable-next-line no-console
            console.log('dx:Existing user found:', cognitoUsername, email);
            if (cognitoUsername) {
                // Determine if the existing user is federated or native
                const isFederated = cognitoUsername.includes('_');
                let destinationProviderName: string;
                let destinationProviderValue: string;

                if (isFederated) {
                    // Federated existing user
                    const [existingProviderName, existingProviderUserId] = cognitoUsername.split('_');
                    destinationProviderName = existingProviderName;
                    destinationProviderValue = existingProviderUserId;
                } else {
                    // Native existing user
                    destinationProviderName = 'Cognito';
                    destinationProviderValue = cognitoUsername;
                }

                const destinationUser = {
                    ProviderName: destinationProviderName,
                    ProviderAttributeValue: destinationProviderValue
                };

                const sourceUser = {
                    ProviderName: providerName,
                    ProviderAttributeName: 'Cognito_Subject',
                    ProviderAttributeValue: providerUserId
                };

                try {
                    await client
                        .adminLinkProviderForUser({ UserPoolId: userPoolId, DestinationUser: destinationUser, SourceUser: sourceUser })
                        .promise();
                    // eslint-disable-next-line no-console
                    console.log(`Linked ${providerName} to existing user ${cognitoUsername}`);
                } catch (linkErr: any) {
                    console.error('Error linking provider:', linkErr.message);
                    throw linkErr;
                }
                // Skip creating new user
                event.response.autoConfirmUser = true;
                event.response.autoVerifyEmail = true;
                return event;
            }
        }

        // 3️⃣ No existing user found → let Cognito create new federated user
        // eslint-disable-next-line no-console
        console.log('No existing user found, allowing Cognito to create new user');
        event.response.autoConfirmUser = true;
        event.response.autoVerifyEmail = true;
        return event;
    }
    return event;
}

import { PreSignUpTriggerEvent } from 'aws-lambda';
import { CognitoIdentityServiceProvider } from 'aws-sdk';

const EXTERNAL_AUTH = 'PreSignUp_ExternalProvider';

function getCognitoClient(region: string) {
    return new CognitoIdentityServiceProvider({ region });
}

function getProviderName(providerRaw: string): string | undefined {
    const map: Record<string, string> = {
        google: 'Google',
        facebook: 'Facebook',
        linkedin: 'LinkedIn'
    };
    return map[providerRaw.toLowerCase()];
}

async function findUserByEmail(client: CognitoIdentityServiceProvider, poolId: string, email: string) {
    const res = await client
        .listUsers({
            UserPoolId: poolId,
            Filter: `email = "${email}"`
        })
        .promise();

    return res.Users ?? [];
}

async function linkAccounts(
    client: CognitoIdentityServiceProvider,
    poolId: string,
    destinationUsername: string,
    providerName: string,
    providerUserId: string
) {
    console.log('dx: linking →', providerName, providerUserId);

    return client
        .adminLinkProviderForUser({
            UserPoolId: poolId,
            DestinationUser: {
                ProviderName: 'Cognito',
                ProviderAttributeValue: destinationUsername
            },
            SourceUser: {
                ProviderName: providerName,
                ProviderAttributeName: 'Cognito_Subject',
                ProviderAttributeValue: providerUserId
            }
        })
        .promise();
}

export async function handler(event: PreSignUpTriggerEvent): Promise<PreSignUpTriggerEvent> {
    console.log('dx:event:', JSON.stringify(event));

    if (event.triggerSource !== EXTERNAL_AUTH) {
        return event;
    }

    const region = event.region;
    const poolId = event.userPoolId;
    const email = event.request.userAttributes.email;
    const rawUserName = event.userName;

    const client = getCognitoClient(region);

    // Extract providerName and providerUserId from "Provider_providerUserId"
    const [providerRaw, providerUserId] = rawUserName.split('_');
    const providerName = getProviderName(providerRaw);

    if (!providerName) {
        console.log('dx: unknown provider →', providerRaw);
        return event;
    }

    // Special handling for LinkedIn (OIDC)
    const isLinkedIn = providerName === 'LinkedIn';

    // If LinkedIn: do NOT create users here — skip to let PostConfirmation handle linking
    if (isLinkedIn) {
        console.log('dx: LinkedIn detected → skipping PreSignUp linking');
        return event;
    }

    // Find existing Cognito user by email
    const users = await findUserByEmail(client, poolId, email);

    // Case 1 — user already exists → link provider
    if (users.length > 0) {
        const existingUser = users[0];
        const existingUsername = existingUser.Username!;

        console.log('dx: existing user found →', existingUsername);

        await linkAccounts(client, poolId, existingUsername, providerName, providerUserId);

        // Prevent Cognito from creating a second user
        event.response.autoConfirmUser = true;
        event.response.autoVerifyEmail = true;
        return event;
    }

    // Case 2 — no existing user → allow Cognito to create one
    console.log('dx: new user, letting Cognito create');
    return event;
}

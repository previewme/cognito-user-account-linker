// preSignUpExternal.ts
import { PreSignUpTriggerEvent } from 'aws-lambda';
import AWS from 'aws-sdk';
import { generate } from 'generate-password';

// --- CONSTANTS AND TYPES ---

const EXTERNAL_AUTHENTICATION_PROVIDER = 'PreSignUp_ExternalProvider';
const COGNITO_SUBJECT_ATTRIBUTE = 'Cognito_Subject';

interface Identity {
    providerName: string;
    userId: string;
    issuer?: string;
    primary?: boolean;
}

// --- DEPENDENCIES (Outside Handler for re-use/mocking) ---

// Initialize client outside the handler to take advantage of cold starts
const client = new AWS.CognitoIdentityServiceProvider();

// --- HELPER FUNCTIONS ---

/**
 * Maps raw provider values (e.g., 'google', 'facebook') to Cognito's standard ProviderName (e.g., 'Google', 'Facebook').
 */
function getProviderName(rawProviderValue: string): string {
    const providerMap: Record<string, string> = {
        google: 'Google',
        facebook: 'Facebook',
        linkedin: 'LinkedIn'
    };
    const lowerValue = rawProviderValue.toLowerCase();
    return providerMap[lowerValue] || rawProviderValue;
}

/**
 * Extracts the provider name and user ID from the event.userName.
 * e.g., 'google_12345' -> { providerName: 'Google', providerUserId: '12345' }
 */
function parseSourceUser({ userName }: { userName?: string }): { providerName: string; providerUserId: string } | null {
    if (!userName) return null;

    const userNameParts = userName.split('_');
    if (userNameParts.length < 2) {
        console.error('dx: unexpected event.userName format:', userName);
        return null;
    }
    const rawProviderValue = userNameParts[0];
    const providerUserId = userNameParts.slice(1).join('_');

    const providerName = getProviderName(rawProviderValue);

    return { providerName, providerUserId };
}

/**
 * Implements the adminLinkProviderForUser API call.
 * This is the functional style helper for the core API call.
 */
async function linkProviderForUser({
    userPoolId,
    sourceProviderName,
    sourceProviderUserId,
    destinationProviderName,
    destinationProviderValue
}: {
    userPoolId: string;
    sourceProviderName: string;
    sourceProviderUserId: string;
    destinationProviderName: string;
    destinationProviderValue: string;
}): Promise<'success' | 'skipped'> {
    const source = `${sourceProviderName}_${sourceProviderUserId}`;

    try {
        await client
            .adminLinkProviderForUser({
                UserPoolId: userPoolId,
                DestinationUser: {
                    ProviderName: destinationProviderName,
                    ProviderAttributeValue: destinationProviderValue
                },
                SourceUser: {
                    ProviderName: sourceProviderName,
                    ProviderAttributeName: COGNITO_SUBJECT_ATTRIBUTE,
                    ProviderAttributeValue: sourceProviderUserId
                }
            })
            .promise();

        console.log('dx: adminLinkProviderForUser succeeded', {
            destinationProviderName,
            destinationProviderValue,
            source
        });
        return 'success';
    } catch (err: any) {
        // Handle the specific, known warning/skip case
        if (err.code === 'InvalidParameterException' && String(err.message).includes('Merging is not currently supported')) {
            console.warn('dx: Link skipped - already linked or confirmed user:', err.message);
            return 'skipped';
        }

        // For all other errors, throw the original error
        console.error('dx: adminLinkProviderForUser error:', err);
        throw err;
    }
}

/**
 * Resolves the destination user's provider/value for linking,
 * handling the split for external provider usernames.
 */
function resolveDestination(username: string): { providerName: string; providerAttributeValue: string } {
    if (!username.includes('_')) {
        // Native Cognito user
        return { providerName: 'Cognito', providerAttributeValue: username };
    }
    // External user from a previous link
    const [providerName, providerAttributeValue] = username.split('_');
    return { providerName, providerAttributeValue };
}

// --- MAIN HANDLER LOGIC ---

export async function handler(event: PreSignUpTriggerEvent): Promise<PreSignUpTriggerEvent> {
    console.log('dx:PreSignUp event:', JSON.stringify(event, null, 2));

    // 1. Initial Checks and Extraction
    if (event.triggerSource !== EXTERNAL_AUTHENTICATION_PROVIDER) {
        console.log('dx: not an external provider signup. skipping.');
        return event;
    }

    const { userPoolId } = event;
    const emailRaw = event.request?.userAttributes?.email;
    const sourceUser = parseSourceUser(event);

    if (!emailRaw) {
        console.warn('dx: no email in event.request.userAttributes; skipping');
        return event;
    }
    const email = emailRaw.toLowerCase();

    if (!sourceUser) {
        return event; // Error logged in helper
    }
    const { providerName, providerUserId } = sourceUser;

    console.log('dx: providerName:', providerName, 'providerUserId:', providerUserId, 'email:', email);

    // 2. List existing users by email
    const listResp = await client
        .listUsers({
            UserPoolId: userPoolId,
            Filter: `email = "${email}"`,
            Limit: 5
        })
        .promise();

    const existingUsers = listResp.Users || [];
    console.log('dx: existingUsers count:', existingUsers.length);

    // 3. Handle Existing User Found
    if (existingUsers.length > 0) {
        // Choose the native Cognito user if available, otherwise the first
        const destination = existingUsers.find((u) => !String(u.Username).includes('_')) || existingUsers[0];
        const destinationUsername = destination.Username!;
        console.log('dx: chosen destination Username:', destinationUsername);

        // Get full attributes to inspect identities
        let destFull: any;
        try {
            destFull = await client
                .adminGetUser({
                    UserPoolId: userPoolId,
                    Username: destinationUsername
                })
                .promise();
        } catch (err) {
            console.warn('dx: AdminGetUser failed, falling back to ListUsers data', err);
            destFull = destination;
        }

        const attrs = destFull?.UserAttributes || (destination.Attributes as AWS.CognitoIdentityServiceProvider.AttributeListType) || [];
        const identitiesAttr = attrs.find((a: any) => a.Name === 'identities');
        let identities: Identity[] = [];

        if (identitiesAttr?.Value) {
            try {
                identities = JSON.parse(identitiesAttr.Value);
            } catch (err) {
                console.warn('dx: failed to parse identities JSON', err);
            }
        }

        const existingIdentity = identities.find((id) => String(id.providerName).toLowerCase() === String(providerName).toLowerCase());

        // A. Existing identity found for this provider
        if (existingIdentity) {
            if (String(existingIdentity.userId) === String(providerUserId)) {
                console.log('dx: Destination already has provider with same userId; skipping link.');
            } else {
                console.log('dx: Found stale provider mapping; attempting to disable/unlink stale identity:', existingIdentity.userId);
                try {
                    // Attempt to disable the stale identity
                    await client
                        .adminDisableProviderForUser({
                            UserPoolId: userPoolId,
                            User: {
                                ProviderName: providerName,
                                ProviderAttributeValue: String(existingIdentity.userId)
                            }
                        })
                        .promise();
                    console.log('dx: AdminDisableProviderForUser succeeded for stale identity', existingIdentity.userId);
                } catch (err) {
                    console.warn('dx: AdminDisableProviderForUser failed (continuing):', err);
                }

                // Proceed to link the new one
                const { providerName: destProv, providerAttributeValue: destVal } = resolveDestination(destinationUsername);
                await linkProviderForUser({
                    userPoolId,
                    sourceProviderName: providerName,
                    sourceProviderUserId: providerUserId,
                    destinationProviderName: destProv,
                    destinationProviderValue: destVal
                });
            }
        } else {
            // B. No existing identity for this provider -> link normally
            console.log('dx: No existing identity for provider found. Linking normally.');
            const { providerName: destProv, providerAttributeValue: destVal } = resolveDestination(destinationUsername);
            await linkProviderForUser({
                userPoolId,
                sourceProviderName: providerName,
                sourceProviderUserId: providerUserId,
                destinationProviderName: destProv,
                destinationProviderValue: destVal
            });
        }

        // Finalize event response
        event.response = event.response || {};
        event.response.autoConfirmUser = true;
        event.response.autoVerifyEmail = true;
        return event;
    }

    // 4. Handle No Existing User Found -> Create native Cognito user
    console.log('dx: No existing user for email; creating native Cognito user to link into');

    const createResp = await client
        .adminCreateUser({
            UserPoolId: userPoolId,
            Username: email,
            MessageAction: 'SUPPRESS', // Suppress welcome email
            UserAttributes: [
                { Name: 'email', Value: email },
                { Name: 'email_verified', Value: 'true' }
            ]
        })
        .promise();

    const newUserUsername = createResp.User?.Username;
    if (!newUserUsername) {
        throw new Error('dx: adminCreateUser failed to produce a Username');
    }

    // Set a permanent random password (required for native users)
    await client
        .adminSetUserPassword({
            UserPoolId: userPoolId,
            Username: newUserUsername,
            Password: generate({ length: 32, numbers: true, symbols: true }),
            Permanent: true
        })
        .promise();

    // Link the external provider to the newly created native user
    await linkProviderForUser({
        userPoolId,
        sourceProviderName: providerName,
        sourceProviderUserId: providerUserId,
        destinationProviderName: 'Cognito',
        destinationProviderValue: newUserUsername
    });

    // Finalize event response
    event.response = event.response || {};
    event.response.autoConfirmUser = true;
    event.response.autoVerifyEmail = true;
    return event;
}

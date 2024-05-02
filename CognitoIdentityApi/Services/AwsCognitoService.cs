namespace CognitoIdentityApi.Services;

public class AwsCognitoService : IAwsCognitoService
{
    private readonly AmazonCognitoIdentityProviderClient _cognitoClient;
    private readonly string _cognitoClientId;
    private readonly string _cognitoUserPoolId;
    private readonly string _cognitoClientSecret;

    public AwsCognitoService(
        IConfiguration configuration,
        IAwsCredentialsService awsCredentialsService
    )
    {
        _cognitoClientId =
            configuration["AWS:CognitoClientId"] ?? throw new InvalidOperationException();

        _cognitoUserPoolId =
            configuration["AWS:CognitoUserPoolId"] ?? throw new InvalidOperationException();

        _cognitoClientSecret =
            configuration["AWS:CognitoClientSecret"] ?? throw new InvalidOperationException();

        var cognitoRegion =
            configuration["AWS:CognitoRegion"] ?? throw new InvalidOperationException();

        _cognitoClient = new AmazonCognitoIdentityProviderClient(
            awsCredentialsService.GetCredentials(),
            RegionEndpoint.GetBySystemName(cognitoRegion)
        );
    }

    public async Task<AdminInitiateAuthResponse> AuthenticateUser(string username, string password)
    {
        var secretHash = CalculateSecretHash(username);
        var request = new AdminInitiateAuthRequest
        {
            UserPoolId = _cognitoUserPoolId,
            ClientId = _cognitoClientId,
            AuthFlow = AuthFlowType.ADMIN_NO_SRP_AUTH,
            AuthParameters = new Dictionary<string, string>
            {
                { "USERNAME", username },
                { "PASSWORD", password },
                { "SECRET_HASH", secretHash }
            }
        };

        var result = await _cognitoClient.AdminInitiateAuthAsync(request);

        return result;
    }

    public async Task<RespondToAuthChallengeResponse> RespondToAuthChallengeNewPassRequired(
        string email,
        string newPassword,
        string session
    )
    {
        var request = new RespondToAuthChallengeRequest
        {
            ChallengeName = ChallengeNameType.NEW_PASSWORD_REQUIRED,
            ClientId = _cognitoClientId,
            Session = session,
            ChallengeResponses = new Dictionary<string, string>
            {
                { "USERNAME", email },
                { "NEW_PASSWORD", newPassword },
                { "SECRET_HASH", CalculateSecretHash(email) }
            }
        };

        var result = await _cognitoClient.RespondToAuthChallengeAsync(request);

        return result;
    }

    private string CalculateSecretHash(string username)
    {
        var key = Encoding.UTF8.GetBytes(_cognitoClientSecret);
        var message = Encoding.UTF8.GetBytes(username + _cognitoClientId);

        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(message);

        var result = Convert.ToBase64String(hash);

        return result;
    }
}

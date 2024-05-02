namespace CognitoIdentityApi.Services.Interfaces;

public interface IAwsCognitoService
{
    Task<AdminInitiateAuthResponse> AuthenticateUser(string username, string password);

    Task<RespondToAuthChallengeResponse> RespondToAuthChallengeNewPassRequired(
        string email,
        string newPassword,
        string session
    );
}

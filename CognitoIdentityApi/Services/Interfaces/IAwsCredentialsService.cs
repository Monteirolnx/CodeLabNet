namespace CognitoIdentityApi.Services.Interfaces;

public interface IAwsCredentialsService
{
    BasicAWSCredentials GetCredentials();
}

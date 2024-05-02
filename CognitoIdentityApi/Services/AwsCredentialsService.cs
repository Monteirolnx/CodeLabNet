namespace CognitoIdentityApi.Services;

public class AwsCredentialsService : IAwsCredentialsService
{
    private readonly BasicAWSCredentials _awsCredentials;

    public AwsCredentialsService(IConfiguration configuration)
    {
        var accessKeyId = configuration["AWS:AccountAccessKeyId"];
        var secretAccessKey = configuration["AWS:AccountSecretAccessKey"];

        if (string.IsNullOrEmpty(accessKeyId) || string.IsNullOrEmpty(secretAccessKey))
            throw new InvalidOperationException("AWS credentials are not properly configured.");

        _awsCredentials = new BasicAWSCredentials(accessKeyId, secretAccessKey);
    }

    public BasicAWSCredentials GetCredentials()
    {
        return _awsCredentials;
    }
}

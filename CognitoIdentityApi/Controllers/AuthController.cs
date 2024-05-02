namespace CognitoIdentityApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(IAwsCognitoService cognitoService) : ControllerBase
{
    [HttpPost("login")]
    public async Task<IActionResult> Login(string email, string password)
    {
        try
        {
            var response = await cognitoService.AuthenticateUser(email, password);
            if (response.AuthenticationResult != null)
            {
                return Ok(new { Token = response.AuthenticationResult.IdToken });
            }

            if (response.ChallengeName == ChallengeNameType.NEW_PASSWORD_REQUIRED.ToString())
            {
                return Ok(new { Challenge = "NEW_PASSWORD_REQUIRED", response.Session });
            }

            return BadRequest("Login failed");
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpPost("respondToNewPasswordRequired")]
    public async Task<IActionResult> RespondToNewPasswordRequired(
        string email,
        string newPassword,
        string session
    )
    {
        try
        {
            var response = await cognitoService.RespondToAuthChallengeNewPassRequired(
                email,
                newPassword,
                session
            );

            if (response.AuthenticationResult != null)
            {
                return Ok(new { Token = response.AuthenticationResult.IdToken });
            }

            return BadRequest("Failed to change password.");
        }
        catch (Exception ex)
        {
            return BadRequest($"An error occurred: {ex.Message}");
        }
    }
}

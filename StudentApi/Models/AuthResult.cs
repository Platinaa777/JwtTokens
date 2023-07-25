namespace StudentApi.Models;

public class AuthResult
{
    public string Token { get; set; }
    public bool Result { get; set; }
    public string RefreshToken { get; set; }
}
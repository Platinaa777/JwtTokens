namespace StudentApi.DTOs;

public class TokenRequestDto
{
    public required string Token { get; set; }
    public required string RefreshToken { get; set; }
}
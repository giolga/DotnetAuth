using AutoMapper;
using DotnetAuth.Domain.Contracts;
using DotnetAuth.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;
using System.Text;

namespace DotnetAuth.Service
{
    public class UserService : IUserService
    {
        private readonly ITokenService _tokenService;
        private readonly ICurrentUserService _currentUserService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IMapper _mapper;
        private readonly ILogger<UserService> _logger;

        public UserService(ITokenService tokenService, ICurrentUserService currentUserService, UserManager<ApplicationUser> userManager, IMapper mapper, ILogger<UserService> logger)
        {
            _tokenService = tokenService;
            _currentUserService = currentUserService;
            _userManager = userManager;
            _mapper = mapper;
            _logger = logger;
        }

        public async Task<UserResponse> RegisterAsync(UserRegisterRequest request)
        {
            _logger.LogInformation("Register user");
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                _logger.LogInformation("Email already exists");
                throw new Exception("Email already exists");
            }

            var newUser = _mapper.Map<ApplicationUser>(request);
            newUser.UserName = GenerateUserName(request.FirstName, request.LastName);
            var result = await _userManager.CreateAsync(newUser, request.Password);

            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("Failed to create user: {errors}", errors);
                throw new Exception($"Failed to create user: {errors}");
            }

            _logger.LogInformation("User created successfully");
            await _tokenService.GenerateToken(newUser);
            return _mapper.Map<UserResponse>(newUser);
        }

        private string GenerateUserName(string firstName, string lastName)
        {
            var baseName = $"{firstName} {lastName}".ToLower();
            var userName = baseName;
            var count = 1;

            while (_userManager.Users.Any(u => u.UserName == userName))
            {
                userName = $"{baseName}{count}";
                count++;
            }

            return userName;
        }

        public async Task<UserResponse> LoginAsync(UserLoginRequest request)
        {
            if (request == null)
            {
                _logger.LogError("Login request is null");
                throw new Exception(nameof(request));
            }

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
            {
                _logger.LogError("Invalid email or password");
                throw new Exception("Invalid email or password");
            }

            var token = await _tokenService.GenerateToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();

            using var sha256 = SHA256.Create();
            var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
            user.RefreshToken = Convert.ToBase64String(refreshTokenHash);
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);

            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("Failed to update user: {errors}", errors);
                throw new Exception($"Failed to update user: {errors}");
            }

            var userResponse = _mapper.Map<ApplicationUser, UserResponse>(user);
            userResponse.AccessToken = token;
            userResponse.RefreshToken = refreshToken;

            return userResponse;
        }

        public Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request)
        {
            throw new NotImplementedException();
        }

        public Task DeleteAsync(Guid id)
        {
            throw new NotImplementedException();
        }

        public Task<CurrentUserResponse> GetCurrentUserAsync()
        {
            throw new NotImplementedException();
        }

        public Task<UserResponse> GetUserByIdAsync(Guid id)
        {
            throw new NotImplementedException();
        }

        public Task<CurrentUserResponse> RefreshTokenAsync(RefreshTokenRequest request)
        {
            throw new NotImplementedException();
        }

        public Task<RevokeRefreshToken> RevokeRefreshToken(RefreshTokenRequest refreshTokenRequest)
        {
            throw new NotImplementedException();
        }

    }
}

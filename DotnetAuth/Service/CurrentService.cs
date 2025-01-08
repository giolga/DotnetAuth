using System.Security.Claims;

namespace DotnetAuth.Service
{
    public class CurrentService : ICurrentUserService
    {
        private readonly IHttpContextAccessor _contextAccessor;

        public CurrentService(IHttpContextAccessor contextAccessor)
        {
            this._contextAccessor = contextAccessor;
        }
        public string? GetUserId()
        {
            var userId = _contextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier);
            return userId;
        }
    }
}

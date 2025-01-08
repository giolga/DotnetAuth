namespace DotnetAuth.Domain.Contracts
{
    public class ErrorResponse
    {
        public string Title { get; set; }
        public string StatusCode { get; set; }
        public string Message { get; set; }
    }
}

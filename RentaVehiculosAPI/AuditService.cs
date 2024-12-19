using RentaVehiculosAPI.Data;
using RentaVehiculosAPI.Models;

namespace RentaVehiculosAPI
{
    public interface IAuditService
    {
        Task LogAsync(string userId, string username, string action, string entity, string details);
    }

    public class AuditService : IAuditService
    {
        private readonly AppDbContext _context;

        public AuditService(AppDbContext context)
        {
            _context = context;
        }

        public async Task LogAsync(string userId, string username, string action, string entity, string details)
        {
            var auditLog = new AuditLog
            {
                UserId = userId,
                Username = username,
                Action = action,
                Entity = entity,
                Details = details
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }
    }

}
